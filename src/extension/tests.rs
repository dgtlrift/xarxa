use std::cell::RefCell;
use std::rc::Rc;
use std::vec::Vec;

use super::*;
use crate::iface::Medium;
use crate::stack::test::{inject, ipv6_packet, udp_datagram};
use crate::test_device::{Queue, Sent, TestDevice};
use crate::wire::{HardwareAddress, Icmpv6Message, Icmpv6Packet, IpCidr, ListenSocketAddr, checksum};
use crate::{Pool, Stack};

const OURS: Ipv6Addr = Ipv6Addr::new(0xfd00, 0xa, 0, 0, 0, 0, 0, 1);
const PEER: Ipv6Addr = Ipv6Addr::new(0xfd00, 0xa, 0, 0, 0, 0, 0, 2);
const FAR: Ipv6Addr = Ipv6Addr::new(0xfd00, 0xb, 0, 0, 0, 0, 0, 2);
const LINK_LOCAL: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);

/// The RPL Option's type (RFC 6553), the one these tests' options use: its high bits,
/// 01, say to discard a packet with it when no one recognizes it.
const OPTION: u8 = 0x63;
/// An ICMPv6 type the stack doesn't process: RPL's.
const ICMP_TYPE: u8 = 155;
/// A routing header type: RFC 6554's source routes.
const ROUTING_TYPE: u8 = 3;
/// An IP protocol the stack doesn't carry: SCTP.
const PROTOCOL: u8 = 132;

/// A hook call, as the mock saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Call {
    Attach,
    Timer(Instant),
    Icmpv6(IpInfo, Vec<u8>),
    Option(Path, Vec<u8>),
    Routing(Vec<u8>),
    Egress(Path),
    Transport(IpInfo, Vec<u8>),
    #[cfg(feature = "icmp-errors")]
    IcmpError(IcmpError, u8),
    #[cfg(feature = "local-loss")]
    Loss(u32),
    #[cfg(feature = "neighbor-unreachable")]
    Unreachable(IfaceHandle, Ipv6Addr),
}

/// An extension that records its calls and does what its fields say.
struct Mock {
    calls: Rc<RefCell<Vec<Call>>>,
    /// The timer `on_attach` arms.
    attach_timer: Option<Instant>,
    /// The timer `on_timer` arms next.
    next_timer: Option<Instant>,
    /// What `on_hbh_option` decides, and the data it writes first.
    option_verdict: Verdict,
    rewrite: Option<[u8; 4]>,
    /// What `on_routing_header` decides.
    route: RouteVerdict,
    /// The option `on_egress` adds to the packets this node sends.
    add_option: Option<[u8; 4]>,
    /// Whether `on_icmpv6` answers, with the message echoed back.
    echo: bool,
    /// Whether it takes every ICMP error.
    route_errors: bool,
}

impl Mock {
    fn new() -> (Self, Rc<RefCell<Vec<Call>>>) {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let mock = Self {
            calls: calls.clone(),
            attach_timer: None,
            next_timer: None,
            option_verdict: Verdict::Continue,
            rewrite: None,
            route: RouteVerdict::Deliver,
            add_option: None,
            echo: false,
            route_errors: false,
        };
        (mock, calls)
    }

    fn log(&self, call: Call) {
        self.calls.borrow_mut().push(call);
    }
}

impl Extension for Mock {
    fn on_attach(&mut self, cx: &mut ExtCx<'_, '_>) {
        self.log(Call::Attach);
        cx.set_timer(self.attach_timer);
    }

    fn on_timer(&mut self, cx: &mut ExtCx<'_, '_>) {
        assert_eq!(cx.timer(), None, "disarmed before the call");
        self.log(Call::Timer(cx.now()));
        cx.set_timer(self.next_timer.take());
    }

    fn icmpv6_types(&self) -> &'static [u8] {
        &[ICMP_TYPE]
    }

    fn on_icmpv6(&mut self, cx: &mut ExtCx<'_, '_>, ip: &IpInfo, message: &[u8]) {
        self.log(Call::Icmpv6(*ip, message.to_vec()));
        if self.echo {
            cx.send_icmpv6(ip.dst, ip.src, 255, message).unwrap();
        }
    }

    fn hbh_options(&self) -> &'static [u8] {
        &[OPTION]
    }

    fn on_hbh_option(&mut self, _: &mut ExtCx<'_, '_>, _: &IpInfo, at: Path, data: &mut [u8]) -> Verdict {
        self.log(Call::Option(at, data.to_vec()));
        if let Some(rewrite) = self.rewrite {
            data.copy_from_slice(&rewrite);
        }
        self.option_verdict
    }

    fn routing_types(&self) -> &'static [u8] {
        &[ROUTING_TYPE]
    }

    fn on_routing_header(&mut self, _: &mut ExtCx<'_, '_>, _: &IpInfo, header: &mut [u8]) -> RouteVerdict {
        self.log(Call::Routing(header.to_vec()));
        self.route
    }

    fn on_egress(&mut self, _: &mut ExtCx<'_, '_>, at: Path, packet: &mut Egress<'_>) -> Verdict {
        self.log(Call::Egress(at));
        if at == Path::Originated
            && let Some(data) = self.add_option
            && !packet.dst().is_multicast()
        {
            packet.add_hbh_option(OPTION, &data).unwrap();
        }
        Verdict::Continue
    }

    fn ip_protocols(&self) -> &'static [u8] {
        &[PROTOCOL]
    }

    fn on_transport(&mut self, _: &mut ExtCx<'_, '_>, ip: &IpInfo, packet: PacketBuf) {
        self.log(Call::Transport(*ip, packet.to_vec()));
    }

    #[cfg(feature = "icmp-errors")]
    fn on_icmp_error(&mut self, _: &mut ExtCx<'_, '_>, error: IcmpError, quoted: &[u8]) {
        self.log(Call::IcmpError(error, quoted[6]));
    }

    #[cfg(feature = "icmp-errors")]
    fn route_errors(&self) -> bool {
        self.route_errors
    }

    #[cfg(feature = "local-loss")]
    fn on_local_loss(&mut self, _: &mut ExtCx<'_, '_>, loss: LocalLoss) {
        self.log(Call::Loss(loss.id));
    }

    #[cfg(feature = "neighbor-unreachable")]
    fn on_neighbor_unreachable(&mut self, _: &mut ExtCx<'_, '_>, iface: IfaceHandle, neighbor: Ipv6Addr) {
        self.log(Call::Unreachable(iface, neighbor));
    }
}

/// A stack with one IP-medium interface, owning [`OURS`]/64 and [`LINK_LOCAL`], with
/// `mock` registered.
fn stack_with(mock: Mock) -> (Stack<'static>, TestDevice, IfaceHandle) {
    let device = TestDevice::new(Medium::Ip);
    let mut stack = Stack::new(crate::pool::test_pool(), 0x1234_5678_dead_beef);
    let iface = device.install(&mut stack, HardwareAddress::Ip);
    stack
        .iface(iface)
        .set_ip_addrs([IpCidr::new(OURS.into(), 64), IpCidr::new(LINK_LOCAL.into(), 64)])
        .unwrap();
    stack.poll(Instant::ZERO);
    device.tx.borrow_mut().clear();
    stack.add_extension(Box::leak(Box::new(mock))).unwrap();
    (stack, device, iface)
}

/// A router between [`OURS`]'s link and [`FAR`]'s, forwarding, with `mock` registered.
fn router_with(mock: Mock) -> (Stack<'static>, [Queue; 2], [Sent; 2]) {
    let (mut stack, near, _) = stack_with(mock);
    let far = TestDevice::new(Medium::Ip);
    let iface = far.install(&mut stack, HardwareAddress::Ip);
    stack
        .iface(iface)
        .set_ip_addrs([IpCidr::new(Ipv6Addr::new(0xfd00, 0xb, 0, 0, 0, 0, 0, 1).into(), 64)])
        .unwrap();
    stack.poll(Instant::ZERO);
    far.tx.borrow_mut().clear();
    near.tx.borrow_mut().clear();
    stack.set_ipv6_forwarding(true);
    (stack, [near.rx, far.rx], [near.tx, far.tx])
}

/// An ICMPv6 message of `kind` with `body`, its checksum filled in for `src` to `dst`.
fn icmpv6(kind: u8, body: &[u8], src: Ipv6Addr, dst: Ipv6Addr) -> Vec<u8> {
    let mut message = vec![kind, 0, 0, 0];
    message.extend_from_slice(body);
    let sum = !checksum::combine(&[
        checksum::pseudo_header_v6(&src, &dst, IpProtocol::Icmpv6, message.len() as u32),
        checksum::data(&message),
    ]);
    message[2..4].copy_from_slice(&sum.to_be_bytes());
    message
}

/// A hop-by-hop header leading to `next_header`, holding the option [`OPTION`] with
/// `data`.
fn hbh(next_header: IpProtocol, data: [u8; 4]) -> Vec<u8> {
    let mut header = vec![next_header.into(), 0, OPTION, 4];
    header.extend_from_slice(&data);
    header
}

/// A UDP datagram from [`PEER`] to `dst`, behind a hop-by-hop header with the option.
fn udp_with_option(dst: Ipv6Addr, data: [u8; 4]) -> Vec<u8> {
    let mut payload = hbh(IpProtocol::Udp, data);
    payload.extend(udp_datagram(PEER.into(), 1000, dst.into(), 7, b"hello"));
    ipv6_packet(PEER, dst, IpProtocol::HopByHop, &payload)
}

#[test]
fn a_timer_fires_at_its_instant_and_sets_the_deadline() {
    let (mut mock, calls) = Mock::new();
    mock.attach_timer = Some(Instant::from_millis(100));
    mock.next_timer = Some(Instant::from_millis(250));
    let (mut stack, _, _) = stack_with(mock);
    assert_eq!(*calls.borrow(), [Call::Attach]);

    assert_eq!(stack.poll(Instant::from_millis(10)), Instant::from_millis(100));
    assert_eq!(stack.poll(Instant::from_millis(99)), Instant::from_millis(100));
    assert_eq!(calls.borrow().len(), 1);

    // It fires once, and arms the next.
    assert_eq!(stack.poll(Instant::from_millis(100)), Instant::from_millis(250));
    assert_eq!(calls.borrow()[1], Call::Timer(Instant::from_millis(100)));
    assert_eq!(stack.poll(Instant::from_millis(120)), Instant::from_millis(250));
    assert_eq!(calls.borrow().len(), 2);

    // Disarmed, it leaves the deadline to the stack's own timers.
    stack.poll(Instant::from_millis(260));
    assert_eq!(calls.borrow()[2], Call::Timer(Instant::from_millis(260)));
    assert_eq!(
        stack.poll(Instant::from_millis(300)),
        crate::time::idle_deadline(Instant::from_millis(300))
    );
}

#[test]
fn a_timer_set_for_now_asks_for_a_poll_at_once() {
    let (mut mock, calls) = Mock::new();
    mock.attach_timer = Some(Instant::from_millis(5));
    mock.next_timer = Some(Instant::from_millis(5));
    let (mut stack, _, _) = stack_with(mock);
    assert_eq!(stack.poll(Instant::from_millis(5)), Instant::from_millis(6));
    assert_eq!(calls.borrow().len(), 2);
    stack.poll(Instant::from_millis(6));
    assert_eq!(calls.borrow()[2], Call::Timer(Instant::from_millis(6)));
}

#[test]
fn a_woken_extension_fires_at_the_next_poll() {
    let (mut mock, calls) = Mock::new();
    mock.attach_timer = Some(Instant::from_millis(500));
    let (mut stack, _, _) = stack_with(mock);
    assert_eq!(stack.poll(Instant::from_millis(10)), Instant::from_millis(500));
    // Woken, it fires at the next poll, though its timer was later; then the deadline is
    // the stack's own.
    assert!(stack.wake_extension(ExtHandle(0)));
    stack.poll(Instant::from_millis(20));
    assert_eq!(calls.borrow()[1], Call::Timer(Instant::from_millis(20)));
    assert_eq!(calls.borrow().len(), 2);
    // A free slot isn't woken.
    assert!(stack.remove_extension(ExtHandle(0)).is_some());
    assert!(!stack.wake_extension(ExtHandle(0)));
}

#[test]
fn an_icmpv6_type_it_names_is_handed_over_and_answered() {
    let (mut mock, calls) = Mock::new();
    mock.echo = true;
    let (mut stack, device, iface) = stack_with(mock);
    let message = icmpv6(ICMP_TYPE, &[1, 2, 3, 4], PEER, OURS);
    inject(
        &mut stack,
        &device.rx,
        ipv6_packet(PEER, OURS, IpProtocol::Icmpv6, &message),
    );
    let ip = IpInfo {
        src: PEER,
        dst: OURS,
        traffic_class: 0,
        hop_limit: 64,
        iface,
    };
    assert_eq!(calls.borrow()[1], Call::Icmpv6(ip, message.clone()));

    // The answer: the stack wrote the header and the checksum.
    let sent = device.tx.borrow_mut().pop().unwrap();
    assert_eq!(sent[6], u8::from(IpProtocol::Icmpv6));
    assert_eq!(sent[7], 255);
    assert_eq!(&sent[8..24], &OURS.octets());
    assert_eq!(&sent[24..40], &PEER.octets());
    assert_eq!(sent[IPV6_HEADER_LEN..], icmpv6(ICMP_TYPE, &[1, 2, 3, 4], OURS, PEER));

    // A bad checksum is dropped before the extension, and a type it doesn't name isn't its.
    let mut bad = message;
    bad[2] ^= 1;
    inject(
        &mut stack,
        &device.rx,
        ipv6_packet(PEER, OURS, IpProtocol::Icmpv6, &bad),
    );
    let other = icmpv6(156, &[], PEER, OURS);
    inject(
        &mut stack,
        &device.rx,
        ipv6_packet(PEER, OURS, IpProtocol::Icmpv6, &other),
    );
    assert_eq!(calls.borrow().len(), 2);
}

#[test]
fn a_received_option_is_handed_over_and_the_packet_delivered() {
    let (mock, calls) = Mock::new();
    let (mut stack, device, _) = stack_with(mock);
    let socket = stack.add_udp_socket().unwrap();
    stack.udp_socket(socket).bind(7, ListenSocketAddr::UNSPECIFIED).unwrap();
    inject(&mut stack, &device.rx, udp_with_option(OURS, [1, 2, 3, 4]));
    assert_eq!(calls.borrow()[1], Call::Option(Path::Received, vec![1, 2, 3, 4]));
    assert!(stack.udp_socket(socket).recv().is_ok());
}

#[test]
fn an_option_with_no_extension_discards_the_packet() {
    let device = TestDevice::new(Medium::Ip);
    let mut stack = Stack::new(crate::pool::test_pool(), 1);
    let iface = device.install(&mut stack, HardwareAddress::Ip);
    stack.iface(iface).set_ip_addrs([IpCidr::new(OURS.into(), 64)]).unwrap();
    let socket = stack.add_udp_socket().unwrap();
    stack.udp_socket(socket).bind(7, ListenSocketAddr::UNSPECIFIED).unwrap();
    inject(&mut stack, &device.rx, udp_with_option(OURS, [1, 2, 3, 4]));
    assert!(stack.udp_socket(socket).recv().is_err());
}

#[test]
fn a_discarding_verdict_drops_the_packet_or_sends_an_error() {
    let (mut mock, _) = Mock::new();
    mock.option_verdict = Verdict::Discard;
    let (mut stack, device, _) = stack_with(mock);
    let socket = stack.add_udp_socket().unwrap();
    stack.udp_socket(socket).bind(7, ListenSocketAddr::UNSPECIFIED).unwrap();
    inject(&mut stack, &device.rx, udp_with_option(OURS, [1, 2, 3, 4]));
    assert!(stack.udp_socket(socket).recv().is_err());
    assert!(device.tx.borrow().is_empty());

    let (mut mock, _) = Mock::new();
    mock.option_verdict = Verdict::DiscardSendError { code: 0, pointer: 1 };
    let (mut stack, device, _) = stack_with(mock);
    inject(&mut stack, &device.rx, udp_with_option(OURS, [1, 2, 3, 4]));
    let sent = device.tx.borrow_mut().pop().unwrap();
    let mut error = sent[IPV6_HEADER_LEN..].to_vec();
    let error = Icmpv6Packet::new_checked(&mut error[..]).unwrap();
    assert_eq!(error.msg_type(), Icmpv6Message::ParamProblem);
    // The data starts 4 octets into the hop-by-hop header, after the IPv6 header.
    assert_eq!(error.param_problem_ptr(), (IPV6_HEADER_LEN + 4 + 1) as u32);
}

#[test]
fn an_option_is_added_on_egress_and_the_datagram_stays_valid() {
    let (mut mock, calls) = Mock::new();
    mock.add_option = Some([9, 8, 7, 6]);
    let (mut stack, device, _) = stack_with(mock);
    let socket = stack.add_udp_socket().unwrap();
    stack
        .udp_socket(socket)
        .bind(1000, ListenSocketAddr::UNSPECIFIED)
        .unwrap();
    stack
        .udp_socket(socket)
        .send_slice(b"hello", crate::wire::SocketAddr::new(PEER.into(), 7))
        .unwrap();
    stack.poll(Instant::ZERO);
    assert_eq!(calls.borrow()[1], Call::Egress(Path::Originated));

    let sent = device.tx.borrow_mut().pop().unwrap();
    assert_eq!(sent[6], u8::from(IpProtocol::HopByHop));
    assert_eq!(
        &sent[IPV6_HEADER_LEN..IPV6_HEADER_LEN + 8],
        hbh(IpProtocol::Udp, [9, 8, 7, 6])
    );
    let udp = &sent[IPV6_HEADER_LEN + 8..];
    assert_eq!(usize::from(u16::from_be_bytes([sent[4], sent[5]])), 8 + udp.len());
    assert_eq!(udp, udp_datagram(OURS.into(), 1000, PEER.into(), 7, b"hello"));
}

#[test]
fn an_option_joins_an_existing_header() {
    let mut storage = crate::pool::test_pool().alloc().unwrap();
    let mut payload = vec![u8::from(IpProtocol::Udp), 0, 0x05, 0x02, 0, 0, 0x01, 0x00];
    payload.extend_from_slice(&[0xaa; 8]);
    let packet = ipv6_packet(OURS, PEER, IpProtocol::HopByHop, &payload);
    storage.reserve(64);
    storage.set_len(packet.len());
    storage.copy_from_slice(&packet);
    let mut egress = Egress::new(&mut storage, 0);
    egress.add_hbh_option(OPTION, &[1, 2, 3, 4]).unwrap();
    assert_eq!(egress.hbh_option_mut(OPTION).unwrap(), &mut [1, 2, 3, 4]);
    let packet = egress.packet();
    // Router alert, then the option, then 4 octets of PadN: 16 octets in all.
    assert_eq!(
        &packet[IPV6_HEADER_LEN..IPV6_HEADER_LEN + 16],
        &[17, 1, 0x05, 0x02, 0, 0, OPTION, 4, 1, 2, 3, 4, 0x01, 0x02, 0, 0]
    );
    assert_eq!(&packet[IPV6_HEADER_LEN + 16..], &[0xaa; 8]);
    assert_eq!(u16::from_be_bytes([packet[4], packet[5]]), 24);
    assert_eq!(egress.add_hbh_option(OPTION, &[0; 64]), Err(SendError::BufferFull));
}

#[test]
fn a_forwarded_option_is_rewritten() {
    let (mut mock, calls) = Mock::new();
    mock.rewrite = Some([5, 5, 5, 5]);
    let (mut stack, rx, tx) = router_with(mock);
    inject(&mut stack, &rx[0], udp_with_option(FAR, [1, 2, 3, 4]));
    assert_eq!(
        calls.borrow()[1..],
        [
            Call::Option(Path::Forwarded, vec![1, 2, 3, 4]),
            Call::Egress(Path::Forwarded)
        ]
    );
    let sent = tx[1].borrow_mut().pop().unwrap();
    assert_eq!(sent[7], 63);
    assert_eq!(&sent[IPV6_HEADER_LEN + 4..IPV6_HEADER_LEN + 8], &[5, 5, 5, 5]);
}

/// A packet for this node with a routing header of [`ROUTING_TYPE`] leading to UDP.
fn routed_packet() -> Vec<u8> {
    let mut payload = vec![u8::from(IpProtocol::Udp), 0, ROUTING_TYPE, 1, 0, 0, 0, 0];
    payload.extend(udp_datagram(PEER.into(), 1000, OURS.into(), 7, b"hello"));
    ipv6_packet(PEER, OURS, IpProtocol::Ipv6Route, &payload)
}

#[test]
fn a_routing_header_is_handed_over_and_the_packet_sent_on() {
    let (mut mock, calls) = Mock::new();
    mock.route = RouteVerdict::Forward(FAR);
    let (mut stack, rx, tx) = router_with(mock);
    inject(&mut stack, &rx[0], routed_packet());
    assert_eq!(
        calls.borrow()[1],
        Call::Routing(vec![17, 0, ROUTING_TYPE, 1, 0, 0, 0, 0])
    );
    let sent = tx[1].borrow_mut().pop().unwrap();
    assert_eq!(&sent[24..40], &FAR.octets());
}

#[test]
fn a_delivered_routing_header_goes_on_to_the_transport() {
    let (mock, calls) = Mock::new();
    let (mut stack, device, _) = stack_with(mock);
    let socket = stack.add_udp_socket().unwrap();
    stack.udp_socket(socket).bind(7, ListenSocketAddr::UNSPECIFIED).unwrap();
    inject(&mut stack, &device.rx, routed_packet());
    assert_eq!(calls.borrow().len(), 2);
    assert!(stack.udp_socket(socket).recv().is_ok());
}

#[test]
fn a_transport_packet_and_an_error_quoting_it_are_handed_over() {
    let (mock, calls) = Mock::new();
    let (mut stack, device, iface) = stack_with(mock);
    let segment = [0x13, 0x88, 0x13, 0x89, 0, 0, 0, 1, 0xab];
    let packet = ipv6_packet(PEER, OURS, IpProtocol::from(PROTOCOL), &segment);
    inject(&mut stack, &device.rx, packet);
    let ip = IpInfo {
        src: PEER,
        dst: OURS,
        traffic_class: 0,
        hop_limit: 64,
        iface,
    };
    assert_eq!(calls.borrow()[1], Call::Transport(ip, segment.to_vec()));

    #[cfg(feature = "icmp-errors")]
    {
        let quoted = ipv6_packet(OURS, PEER, IpProtocol::from(PROTOCOL), &segment);
        let mut body = vec![0; 4];
        body.extend_from_slice(&quoted);
        let error = icmpv6(Icmpv6Message::DstUnreachable.into(), &body, PEER, OURS);
        inject(
            &mut stack,
            &device.rx,
            ipv6_packet(PEER, OURS, IpProtocol::Icmpv6, &error),
        );
        assert_eq!(calls.borrow()[2], Call::IcmpError(IcmpError::NetUnreachable, PROTOCOL));
    }
}

#[cfg(feature = "local-loss")]
#[test]
fn a_local_loss_of_its_protocol_is_handed_over() {
    let (mock, calls) = Mock::new();
    let (mut stack, device, _) = stack_with(mock);
    device.losses.borrow_mut().push_back(LocalLoss {
        transport: PROTOCOL,
        id: 42,
        reason: crate::driver::LossReason::NoAck,
    });
    stack.poll(Instant::ZERO);
    assert_eq!(calls.borrow()[1], Call::Loss(42));
}

#[cfg(all(feature = "icmp-errors", feature = "udp"))]
#[test]
fn a_routing_extension_takes_an_error_quoting_a_udp_datagram() {
    let (mut mock, calls) = Mock::new();
    mock.route_errors = true;
    let (mut stack, device, _) = stack_with(mock);
    let quoted = ipv6_packet(
        OURS,
        FAR,
        IpProtocol::Udp,
        &udp_datagram(OURS.into(), 5000, FAR.into(), 5001, b"hi"),
    );
    let mut body = vec![0; 4];
    body.extend_from_slice(&quoted);
    let error = icmpv6(Icmpv6Message::DstUnreachable.into(), &body, PEER, OURS);
    inject(
        &mut stack,
        &device.rx,
        ipv6_packet(PEER, OURS, IpProtocol::Icmpv6, &error),
    );
    assert_eq!(
        calls.borrow()[1..],
        [Call::IcmpError(IcmpError::NetUnreachable, u8::from(IpProtocol::Udp))]
    );
}

#[cfg(feature = "icmp-errors")]
#[test]
fn an_error_goes_once_to_a_routing_extension_that_carries_the_protocol() {
    let (mut mock, calls) = Mock::new();
    mock.route_errors = true;
    let (mut stack, device, _) = stack_with(mock);
    let quoted = ipv6_packet(
        OURS,
        PEER,
        IpProtocol::from(PROTOCOL),
        &[0x13, 0x88, 0x13, 0x89, 0, 0, 0, 1],
    );
    let mut body = vec![0; 4];
    body.extend_from_slice(&quoted);
    let error = icmpv6(Icmpv6Message::DstUnreachable.into(), &body, PEER, OURS);
    inject(
        &mut stack,
        &device.rx,
        ipv6_packet(PEER, OURS, IpProtocol::Icmpv6, &error),
    );
    assert_eq!(
        calls.borrow()[1..],
        [Call::IcmpError(IcmpError::NetUnreachable, PROTOCOL)]
    );
}

#[cfg(all(feature = "icmp-errors", feature = "udp"))]
#[test]
fn an_error_quoting_a_udp_datagram_skips_other_extensions() {
    let (mock, calls) = Mock::new();
    let (mut stack, device, _) = stack_with(mock);
    let quoted = ipv6_packet(
        OURS,
        FAR,
        IpProtocol::Udp,
        &udp_datagram(OURS.into(), 5000, FAR.into(), 5001, b"hi"),
    );
    let mut body = vec![0; 4];
    body.extend_from_slice(&quoted);
    let error = icmpv6(Icmpv6Message::DstUnreachable.into(), &body, PEER, OURS);
    inject(
        &mut stack,
        &device.rx,
        ipv6_packet(PEER, OURS, IpProtocol::Icmpv6, &error),
    );
    assert_eq!(calls.borrow()[1..], []);
}

#[cfg(feature = "neighbor-unreachable")]
#[test]
fn an_unreachable_neighbor_is_handed_over() {
    let (mock, calls) = Mock::new();
    let (mut stack, device, iface) = stack_with(mock);
    device.unreachable.borrow_mut().push_back(PEER.into());
    stack.poll(Instant::ZERO);
    assert_eq!(calls.borrow()[1..], [Call::Unreachable(iface, PEER)]);
}

#[test]
fn slots_are_fixed_and_freed_by_removal() {
    let (mock, _) = Mock::new();
    let (mut stack, _, _) = stack_with(mock);
    let (extra, calls) = Mock::new();
    let extra: &'static mut Mock = Box::leak(Box::new(extra));
    if crate::config::EXTENSION_COUNT == 1 {
        assert!(stack.add_extension(extra).is_err());
        assert!(calls.borrow().is_empty());
        let removed = stack.remove_extension(ExtHandle(0));
        assert!(removed.is_some());
        assert!(stack.remove_extension(ExtHandle(0)).is_none());
    }
}
