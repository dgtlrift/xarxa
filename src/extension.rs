//! Extensions: protocols added to the stack without changing its core, such as a
//! routing protocol (RPL, RFC 6550) or a transport (SCTP).
//!
//! An [`Extension`] is registered with [`Stack::add_extension`](crate::Stack::add_extension)
//! and called at fixed points of the stack's processing:
//!
//! - **ICMPv6 messages** of the types it names, which the stack would otherwise drop
//!   ([`on_icmpv6`](Extension::on_icmpv6)).
//! - **Hop-by-hop options** of the types it names, on a packet received for this node or
//!   being forwarded ([`on_hbh_option`](Extension::on_hbh_option)).
//! - **Routing headers** of the types it names, on a packet for this node
//!   ([`on_routing_header`](Extension::on_routing_header)).
//! - **Every IPv6 packet this node sends or forwards**, after the route lookup and before
//!   the interface, to add or rewrite an option ([`on_egress`](Extension::on_egress)).
//! - **Transport packets** of the IP protocols it names, the ICMP errors quoting them and
//!   the drivers' reports of their loss ([`on_transport`](Extension::on_transport)).
//! - **Its timer** ([`on_timer`](Extension::on_timer)), armed with
//!   [`ExtCx::set_timer`]. [`Stack::poll`](crate::Stack::poll) fires it once its instant
//!   has come, and counts it in the deadline it returns, so an application that waits on
//!   that deadline wakes for the timer and never polls on a cadence. The application
//!   fires it at the next poll with [`Stack::wake_extension`](crate::Stack::wake_extension),
//!   after changing state the extension acts on.
//!
//! Each hook runs with its extension taken out of its slot, and gets an [`ExtCx`]: the
//! time, its timer, the route table, the interfaces, and a way to send. A hook can't
//! reach another extension, nor its own slot.
//!
//! An extension that keeps state the application reads, such as a routing protocol's
//! rank, holds it through a shared reference (a `RefCell` the application owns), since
//! the stack holds the extension itself.

#[cfg(feature = "local-loss")]
use crate::driver::LocalLoss;
use crate::driver::PacketBuf;
#[cfg(feature = "icmp-errors")]
use crate::error::IcmpError;
use crate::iface::{Iface, IfaceHandle};
use crate::route::Routes;
use crate::stack::{Blocked, IfaceBinding, TxContext};
use crate::time::Instant;
use crate::wire::{IPV6_HEADER_LEN, IpAddr, IpProtocol, Ipv6Addr, Ipv6ExtHeader, Ipv6OptionType, Ipv6Packet};

/// A protocol added to the stack without changing its core.
///
/// Every method has a default body, so an extension implements only what it uses. See the
/// [module documentation](self) for when each is called.
pub trait Extension {
    /// Called once, when it's registered: to join groups and arm its first timer.
    fn on_attach(&mut self, cx: &mut ExtCx<'_, '_>) {
        let _ = cx;
    }

    /// Its timer fired: the instant it last set with [`ExtCx::set_timer`] has come. The
    /// timer is disarmed before the call.
    fn on_timer(&mut self, cx: &mut ExtCx<'_, '_>) {
        let _ = cx;
    }

    /// The ICMPv6 types it takes, of those the stack doesn't process itself.
    fn icmpv6_types(&self) -> &'static [u8] {
        &[]
    }

    /// A message of one of [`icmpv6_types`](Self::icmpv6_types), addressed to this node:
    /// from its type to its end, its checksum checked.
    fn on_icmpv6(&mut self, cx: &mut ExtCx<'_, '_>, ip: &IpInfo, message: &[u8]) {
        let _ = (cx, ip, message);
    }

    /// The hop-by-hop option types it processes.
    fn hbh_options(&self) -> &'static [u8] {
        &[]
    }

    /// An option of one of [`hbh_options`](Self::hbh_options), on a packet received for
    /// this node or being forwarded: its data, which it may rewrite in place.
    ///
    /// A [`Verdict::DiscardSendError`] pointer counts from the start of `data`.
    fn on_hbh_option(&mut self, cx: &mut ExtCx<'_, '_>, ip: &IpInfo, at: Path, data: &mut [u8]) -> Verdict {
        let _ = (cx, ip, at, data);
        Verdict::Continue
    }

    /// The routing header types it processes.
    fn routing_types(&self) -> &'static [u8] {
        &[]
    }

    /// A routing header of one of [`routing_types`](Self::routing_types), on a packet for
    /// this node: the whole header, from its next header field, which it may rewrite.
    fn on_routing_header(&mut self, cx: &mut ExtCx<'_, '_>, ip: &IpInfo, header: &mut [u8]) -> RouteVerdict {
        let _ = (cx, ip, header);
        RouteVerdict::Deliver
    }

    /// Each IPv6 packet this node sends or forwards, after the route lookup and before the
    /// interface: to add or rewrite an option.
    ///
    /// A [`Verdict::DiscardSendError`] on a forwarded packet sends the error to its source,
    /// its pointer counting from the start of the packet; on a packet this node sends, it
    /// only discards it.
    fn on_egress(&mut self, cx: &mut ExtCx<'_, '_>, at: Path, packet: &mut Egress<'_>) -> Verdict {
        let _ = (cx, at, packet);
        Verdict::Continue
    }

    /// The IP protocols it carries as a transport.
    fn ip_protocols(&self) -> &'static [u8] {
        &[]
    }

    /// A packet of one of [`ip_protocols`](Self::ip_protocols), addressed to this node:
    /// from its transport header to its end.
    fn on_transport(&mut self, cx: &mut ExtCx<'_, '_>, ip: &IpInfo, packet: PacketBuf) {
        let _ = (cx, ip, packet);
    }

    /// An ICMP error quoting a packet of one of [`ip_protocols`](Self::ip_protocols):
    /// `quoted` is that packet, from its IP header, as much of it as the error carries.
    #[cfg(feature = "icmp-errors")]
    fn on_icmp_error(&mut self, cx: &mut ExtCx<'_, '_>, error: IcmpError, quoted: &[u8]) {
        let _ = (cx, error, quoted);
    }

    /// A driver lost a packet of one of [`ip_protocols`](Self::ip_protocols) before it
    /// left the link (`Driver::poll_local_loss`).
    #[cfg(feature = "local-loss")]
    fn on_local_loss(&mut self, cx: &mut ExtCx<'_, '_>, loss: LocalLoss) {
        let _ = (cx, loss);
    }
}

/// A handle to an extension registered with
/// [`Stack::add_extension`](crate::Stack::add_extension).
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExtHandle(usize);

impl ExtHandle {
    pub(crate) fn index(self) -> usize {
        self.0
    }
}

/// The IPv6 header fields of a packet a hook is given.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpInfo {
    /// The source address.
    pub src: Ipv6Addr,
    /// The destination address.
    pub dst: Ipv6Addr,
    /// The Traffic Class.
    pub traffic_class: u8,
    /// The hop limit, as it arrived.
    pub hop_limit: u8,
    /// The interface it arrived on.
    pub iface: IfaceHandle,
}

impl IpInfo {
    /// The fields of `header`, an IPv6 header.
    fn of(header: &[u8; IPV6_HEADER_LEN], iface: IfaceHandle) -> Self {
        Self {
            src: src_of(header),
            dst: dst_of(header),
            traffic_class: (header[0] << 4) | (header[1] >> 4),
            hop_limit: header[7],
            iface,
        }
    }
}

/// Where a packet is in the stack when a hook sees it.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Path {
    /// Received, for this node.
    Received,
    /// Received for another node, being forwarded.
    Forwarded,
    /// Sent by this node.
    Originated,
}

/// What a hook decides about a packet.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Go on with it.
    Continue,
    /// Discard it silently.
    Discard,
    /// Discard it, and send its source an ICMPv6 Parameter Problem with `code` and
    /// `pointer` (RFC 4443 section 3.4). Where the pointer counts from is the hook's to say.
    DiscardSendError {
        /// The Parameter Problem code.
        code: u8,
        /// The offset of the problem.
        pointer: u32,
    },
}

/// What [`Extension::on_routing_header`] decides about a packet.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteVerdict {
    /// The packet is for this node: go on at the header after the routing header.
    Deliver,
    /// Send it on to the given address: the stack writes it as the destination and
    /// forwards the packet, decrementing its hop limit.
    Forward(Ipv6Addr),
    /// Discard it silently.
    Discard,
}

/// Why [`ExtCx`] couldn't send a packet, or [`Egress`] couldn't add an option.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendError {
    /// There is no route to the destination, or the addresses are unspecified.
    Unaddressable,
    /// The packet doesn't fit in a packet buffer, or the option in the hop-by-hop
    /// header.
    BufferFull,
    /// No packet buffer is free.
    NoBuffer,
    /// The interface the packet would go out of has no room for it right now.
    DeviceBusy,
}

impl core::fmt::Display for SendError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SendError::Unaddressable => write!(f, "unaddressable"),
            SendError::BufferFull => write!(f, "buffer full"),
            SendError::NoBuffer => write!(f, "no buffer"),
            SendError::DeviceBusy => write!(f, "device busy"),
        }
    }
}

impl core::error::Error for SendError {}

/// What the stack lends a hook.
pub struct ExtCx<'a, 'd> {
    pub(crate) tx: TxContext<'a, 'd>,
    timer: &'a mut Option<Instant>,
}

impl<'d> ExtCx<'_, 'd> {
    /// The time of the poll in progress, or of the last one.
    pub fn now(&self) -> Instant {
        self.tx.inner.now
    }

    /// Arms the extension's one timer for `at`, or disarms it with `None`.
    ///
    /// An extension with more timers arms the earliest. A timer due when it's set fires at
    /// the next poll, which [`Stack::poll`](crate::Stack::poll) asks for at once.
    pub fn set_timer(&mut self, at: Option<Instant>) {
        *self.timer = at;
    }

    /// The instant the timer is armed for.
    pub fn timer(&self) -> Option<Instant> {
        *self.timer
    }

    /// The route table.
    pub fn routes(&self) -> &Routes {
        &self.tx.inner.routes
    }

    /// The route table, to change it.
    pub fn routes_mut(&mut self) -> &mut Routes {
        &mut self.tx.inner.routes
    }

    /// An interface, for its addresses and groups.
    ///
    /// # Panics
    /// Panics if the handle is stale (the interface was removed).
    pub fn iface(&mut self, handle: IfaceHandle) -> Iface<'_, 'd> {
        self.tx.ifaces.get(handle.index());
        Iface {
            inner: &mut *self.tx.inner,
            ifaces: &mut *self.tx.ifaces,
            index: handle.index(),
        }
    }

    /// Sends an ICMPv6 message from `src` to `dst`, from its type to its end: the stack
    /// writes the checksum and the IPv6 header, and routes it. A multicast destination
    /// goes out of the first interface.
    ///
    /// # Errors
    /// [`SendError`] if it can't be routed, built or queued.
    pub fn send_icmpv6(
        &mut self,
        src: Ipv6Addr,
        dst: Ipv6Addr,
        hop_limit: u8,
        message: &[u8],
    ) -> Result<(), SendError> {
        self.send(src, dst, IpProtocol::Icmpv6, hop_limit, 0, message)
    }

    /// Sends a transport packet of `protocol` with the source, destination, hop limit and
    /// Traffic Class of `ip`; `ip.iface` is ignored, as the packet is routed. The payload
    /// goes as it is: its checksum is the extension's to write.
    ///
    /// # Errors
    /// [`SendError`] if it can't be routed, built or queued.
    pub fn send_ip(&mut self, ip: &IpInfo, protocol: u8, payload: &[u8]) -> Result<(), SendError> {
        self.send(
            ip.src,
            ip.dst,
            IpProtocol::from(protocol),
            ip.hop_limit,
            ip.traffic_class,
            payload,
        )
    }

    fn send(
        &mut self,
        src: Ipv6Addr,
        dst: Ipv6Addr,
        protocol: IpProtocol,
        hop_limit: u8,
        traffic_class: u8,
        payload: &[u8],
    ) -> Result<(), SendError> {
        if src.is_unspecified() || dst.is_unspecified() {
            return Err(SendError::Unaddressable);
        }
        let route = self
            .tx
            .route(IfaceBinding::Any, &IpAddr::V6(dst))
            .ok_or(SendError::Unaddressable)?;
        self.tx.can_transmit(route.iface).map_err(|blocked| match blocked {
            Blocked::DeviceBusy => SendError::DeviceBusy,
            Blocked::NoBuffer => SendError::NoBuffer,
        })?;
        let mut buf = self.tx.inner.pool.alloc().ok_or(SendError::NoBuffer)?;
        let headroom = route.ip_headroom + IPV6_HEADER_LEN;
        if headroom + payload.len() > buf.capacity() {
            return Err(SendError::BufferFull);
        }
        buf.reserve(headroom);
        buf.set_len(payload.len());
        buf.copy_from_slice(payload);
        if protocol == IpProtocol::Icmpv6 {
            let mut packet = crate::wire::Icmpv6Packet::new_unchecked(&mut buf[..]);
            if self.tx.ifaces.get(route.iface.index()).checksum_caps().icmpv6.tx {
                packet.set_checksum(0);
            } else {
                packet.fill_checksum(&src, &dst);
            }
        }
        self.tx.transmit_ip(
            &route,
            buf,
            IpAddr::V6(src),
            IpAddr::V6(dst),
            protocol,
            hop_limit,
            traffic_class,
        );
        Ok(())
    }
}

/// An IPv6 packet on its way out, given to [`Extension::on_egress`]: its header, and room
/// to insert a hop-by-hop option.
pub struct Egress<'a> {
    buf: &'a mut PacketBuf,
    /// The headroom the egress interface needs in front of the packet.
    headroom: usize,
}

/// The most option data a hop-by-hop header [`Egress::add_hbh_option`] builds can hold.
const MAX_HBH_OPTIONS: usize = 64;

impl<'a> Egress<'a> {
    pub(crate) fn new(buf: &'a mut PacketBuf, headroom: usize) -> Self {
        Self { buf, headroom }
    }

    /// The packet, from its IPv6 header.
    pub fn packet(&self) -> &[u8] {
        self.buf
    }

    /// Its IPv6 header.
    pub fn header(&self) -> &[u8] {
        &self.buf[..IPV6_HEADER_LEN]
    }

    /// Its source address.
    pub fn src(&self) -> Ipv6Addr {
        src_of(self.fixed())
    }

    /// Its destination address.
    pub fn dst(&self) -> Ipv6Addr {
        dst_of(self.fixed())
    }

    fn fixed(&self) -> &[u8; IPV6_HEADER_LEN] {
        self.buf[..IPV6_HEADER_LEN].try_into().unwrap()
    }

    /// The data of its hop-by-hop option of type `kind`, if it has one.
    pub fn hbh_option_mut(&mut self, kind: u8) -> Option<&mut [u8]> {
        let (start, len) = find_option(&self.buf[..], kind)?;
        self.buf.get_mut(start..start + len)
    }

    /// Adds a hop-by-hop option of type `kind` with `data`, creating the header if the
    /// packet has none, and padding it to a multiple of 8 octets.
    ///
    /// # Errors
    /// - [`SendError::BufferFull`]: the options would be longer than the stack builds, or
    ///   the packet with them wouldn't fit its buffer. The packet is unchanged.
    pub fn add_hbh_option(&mut self, kind: u8, data: &[u8]) -> Result<(), SendError> {
        let data_len = u8::try_from(data.len()).map_err(|_| SendError::BufferFull)?;
        // The options the packet has now, without their padding.
        let mut options = [0u8; MAX_HBH_OPTIONS];
        let mut used = 0;
        let (old_len, next_header) = {
            let next_header = next_header_of(&self.buf[..]);
            if next_header == IpProtocol::HopByHop {
                let ext =
                    Ipv6ExtHeader::new_checked(&self.buf[IPV6_HEADER_LEN..]).map_err(|_| SendError::BufferFull)?;
                for option in crate::wire::Ipv6OptionsIter::new(ext.data()) {
                    let (_, option_type, option_data) = option.map_err(|_| SendError::BufferFull)?;
                    if matches!(option_type, Ipv6OptionType::Pad1 | Ipv6OptionType::PadN) {
                        continue;
                    }
                    let end = used + 2 + option_data.len();
                    let slot = options.get_mut(used..end).ok_or(SendError::BufferFull)?;
                    slot[0] = option_type.into();
                    slot[1] = option_data.len() as u8;
                    slot[2..].copy_from_slice(option_data);
                    used = end;
                }
                (ext.header_len(), ext.next_header())
            } else {
                (0, next_header)
            }
        };
        let end = used + 2 + data.len();
        let slot = options.get_mut(used..end).ok_or(SendError::BufferFull)?;
        slot[0] = kind;
        slot[1] = data_len;
        slot[2..].copy_from_slice(data);
        used = end;

        // The header: next header, length, the options, then padding.
        let new_len = (2 + used).div_ceil(8) * 8;
        let grow = new_len - old_len;
        if !self.buf.ensure_headroom(self.headroom + grow) {
            return Err(SendError::BufferFull);
        }
        self.buf.push_front(grow);
        self.buf.copy_within(grow..grow + IPV6_HEADER_LEN, 0);
        let header = &mut self.buf[IPV6_HEADER_LEN..IPV6_HEADER_LEN + new_len];
        header[0] = next_header.into();
        header[1] = (new_len / 8 - 1) as u8;
        header[2..2 + used].copy_from_slice(&options[..used]);
        match new_len - 2 - used {
            0 => {}
            1 => header[2 + used] = Ipv6OptionType::Pad1.into(),
            pad => {
                header[2 + used] = Ipv6OptionType::PadN.into();
                header[3 + used] = (pad - 2) as u8;
                header[4 + used..].fill(0);
            }
        }
        let payload_len = self.buf.len() - IPV6_HEADER_LEN;
        let mut packet = Ipv6Packet::new_unchecked(&mut self.buf[..]);
        packet.set_next_header(IpProtocol::HopByHop);
        packet.set_payload_len(payload_len as u16);
        Ok(())
    }
}

/// The offset and length of the data of the hop-by-hop option of type `kind` in `packet`,
/// which starts at its IPv6 header.
fn find_option(packet: &[u8], kind: u8) -> Option<(usize, usize)> {
    if next_header_of(packet) != IpProtocol::HopByHop {
        return None;
    }
    let ext = Ipv6ExtHeader::new_checked(packet.get(IPV6_HEADER_LEN..)?).ok()?;
    let start = IPV6_HEADER_LEN + 2;
    crate::wire::Ipv6OptionsIter::new(ext.data()).find_map(|option| {
        let (offset, option_type, data) = option.ok()?;
        (u8::from(option_type) == kind).then_some((start + offset + 2, data.len()))
    })
}

/// The next header field of `packet`, an IPv6 packet at least as long as its header.
fn next_header_of(packet: &[u8]) -> IpProtocol {
    IpProtocol::from(packet[6])
}

/// The source address in an IPv6 header.
fn src_of(header: &[u8; IPV6_HEADER_LEN]) -> Ipv6Addr {
    Ipv6Addr::from(<[u8; 16]>::try_from(&header[8..24]).unwrap())
}

/// The destination address in an IPv6 header.
fn dst_of(header: &[u8; IPV6_HEADER_LEN]) -> Ipv6Addr {
    Ipv6Addr::from(<[u8; 16]>::try_from(&header[24..40]).unwrap())
}

/// One extension's place in the stack.
struct Slot<'d> {
    /// Whether an extension is registered here.
    used: bool,
    /// The extension, unless a hook is running with it.
    ext: Option<&'d mut dyn Extension>,
    /// When its timer fires.
    timer: Option<Instant>,
}

impl Slot<'_> {
    const EMPTY: Self = Self {
        used: false,
        ext: None,
        timer: None,
    };
}

/// The stack's extensions, in a fixed number of slots.
pub(crate) struct Extensions<'d> {
    slots: [Slot<'d>; crate::config::EXTENSION_COUNT],
}

impl<'d> Extensions<'d> {
    pub(crate) const fn new() -> Self {
        Self {
            slots: [const { Slot::EMPTY }; crate::config::EXTENSION_COUNT],
        }
    }

    /// Puts `ext` in a free slot.
    pub(crate) fn add(&mut self, ext: &'d mut dyn Extension) -> Option<ExtHandle> {
        let index = self.slots.iter().position(|slot| !slot.used)?;
        self.slots[index] = Slot {
            used: true,
            ext: Some(ext),
            timer: None,
        };
        Some(ExtHandle(index))
    }

    /// Takes the extension out of its slot, freeing it.
    pub(crate) fn remove(&mut self, handle: ExtHandle) -> Option<&'d mut dyn Extension> {
        let slot = self.slots.get_mut(handle.index())?;
        let ext = slot.ext.take();
        *slot = Slot::EMPTY;
        ext
    }

    /// Whether no extension is registered, so that the stack's paths skip them at once.
    pub(crate) fn is_empty(&self) -> bool {
        !self.slots.iter().any(|slot| slot.used)
    }

    /// Whether an extension wants what `wants` asks.
    pub(crate) fn any(&self, mut wants: impl FnMut(&dyn Extension) -> bool) -> bool {
        self.slots
            .iter()
            .any(|slot| slot.ext.as_deref().is_some_and(&mut wants))
    }

    /// The armed timers due at `now`, disarmed, as a mask of slots.
    pub(crate) fn take_due(&mut self, now: Instant) -> u32 {
        let mut due = 0;
        for (index, slot) in self.slots.iter_mut().enumerate() {
            if slot.timer.is_some_and(|at| at <= now) {
                slot.timer = None;
                due |= 1 << index;
            }
        }
        due
    }

    /// Arms the timer of the extension in `handle`'s slot for `now`, unless it's armed
    /// sooner; `false` if the slot is free.
    pub(crate) fn wake(&mut self, handle: ExtHandle, now: Instant) -> bool {
        let Some(slot) = self.slots.get_mut(handle.index()).filter(|slot| slot.used) else {
            return false;
        };
        slot.timer = Some(match slot.timer {
            Some(at) if at <= now => at,
            _ => now,
        });
        true
    }

    /// The armed timers.
    pub(crate) fn timers(&self) -> impl Iterator<Item = Instant> + '_ {
        self.slots.iter().filter_map(|slot| slot.timer)
    }
}

impl<'d> TxContext<'_, 'd> {
    /// Calls `hook` on the extension in slot `index`, taken out of it, if there is one and
    /// it `wants` the call.
    fn call_extension<T>(
        &mut self,
        index: usize,
        wants: &mut impl FnMut(&dyn Extension) -> bool,
        hook: &mut impl FnMut(&mut dyn Extension, &mut ExtCx<'_, 'd>) -> T,
    ) -> Option<T> {
        let slot = self.extensions.slots.get_mut(index)?;
        let mut timer = slot.timer;
        let ext = slot.ext.take()?;
        if !wants(&*ext) {
            self.extensions.slots[index].ext = Some(ext);
            return None;
        }
        let result = {
            let mut cx = ExtCx {
                tx: TxContext {
                    inner: &mut *self.inner,
                    ifaces: &mut *self.ifaces,
                    extensions: &mut *self.extensions,
                },
                timer: &mut timer,
            };
            hook(&mut *ext, &mut cx)
        };
        let slot = &mut self.extensions.slots[index];
        slot.ext = Some(ext);
        slot.timer = timer;
        Some(result)
    }

    /// Calls `hook` on the first extension that `wants` the call; `None` if none does.
    pub(crate) fn first_extension<T>(
        &mut self,
        mut wants: impl FnMut(&dyn Extension) -> bool,
        mut hook: impl FnMut(&mut dyn Extension, &mut ExtCx<'_, 'd>) -> T,
    ) -> Option<T> {
        (0..crate::config::EXTENSION_COUNT).find_map(|index| self.call_extension(index, &mut wants, &mut hook))
    }

    /// Calls `hook` on each extension in turn, stopping at the first verdict that isn't
    /// [`Verdict::Continue`].
    pub(crate) fn each_extension(
        &mut self,
        mut hook: impl FnMut(&mut dyn Extension, &mut ExtCx<'_, 'd>) -> Verdict,
    ) -> Verdict {
        (0..crate::config::EXTENSION_COUNT)
            .filter_map(|index| self.call_extension(index, &mut |_: &dyn Extension| true, &mut hook))
            .find(|verdict| *verdict != Verdict::Continue)
            .unwrap_or(Verdict::Continue)
    }

    /// Calls `on_timer` on the extensions in `due`, a mask of slots.
    pub(crate) fn fire_timers(&mut self, due: u32) {
        for index in 0..crate::config::EXTENSION_COUNT {
            if due & (1 << index) != 0 {
                self.call_extension(index, &mut |_: &dyn Extension| true, &mut |ext, cx| ext.on_timer(cx));
            }
        }
    }

    /// Calls `on_attach` on the extension in `handle`'s slot.
    pub(crate) fn attach(&mut self, handle: ExtHandle) {
        self.call_extension(handle.index(), &mut |_: &dyn Extension| true, &mut |ext, cx| {
            ext.on_attach(cx)
        });
    }

    /// Runs the extensions' [`on_egress`](Extension::on_egress) on `buf`, an IPv6 packet
    /// from its header, that needs `headroom` on its interface.
    pub(crate) fn egress(&mut self, at: Path, buf: &mut PacketBuf, headroom: usize) -> Verdict {
        if self.extensions.is_empty() {
            return Verdict::Continue;
        }
        self.each_extension(|ext, cx| ext.on_egress(cx, at, &mut Egress::new(buf, headroom)))
    }

    /// Runs the extensions' [`on_hbh_option`](Extension::on_hbh_option) on each option of
    /// the hop-by-hop header of `packet` that one of them names; the first verdict that
    /// isn't [`Verdict::Continue`], with a pointer from the start of the packet.
    pub(crate) fn hbh_options(&mut self, packet: &mut [u8], at: Path, iface: IfaceHandle) -> Verdict {
        if self.extensions.is_empty() || next_header_of(packet) != IpProtocol::HopByHop {
            return Verdict::Continue;
        }
        let Some(header) = packet.first_chunk::<IPV6_HEADER_LEN>() else {
            return Verdict::Continue;
        };
        let ip = IpInfo::of(header, iface);
        let Some(ext_len) = packet
            .get(IPV6_HEADER_LEN..)
            .and_then(|ext| Ipv6ExtHeader::new_checked(ext).ok())
            .map(|ext| ext.header_len())
        else {
            return Verdict::Continue;
        };
        let options = &mut packet[IPV6_HEADER_LEN + 2..IPV6_HEADER_LEN + ext_len];
        let mut offset = 0;
        while let Some(Ok((_, option_type, data))) = crate::wire::Ipv6OptionsIter::new(&options[offset..]).next() {
            let kind = u8::from(option_type);
            let (start, len) = if option_type == Ipv6OptionType::Pad1 {
                (offset + 1, 0)
            } else {
                (offset + 2, data.len())
            };
            offset = start + len;
            if option_type == Ipv6OptionType::Pad1 {
                continue;
            }
            let data = &mut options[start..start + len];
            let verdict = self
                .first_extension(
                    |ext| ext.hbh_options().contains(&kind),
                    |ext, cx| ext.on_hbh_option(cx, &ip, at, data),
                )
                .unwrap_or(Verdict::Continue);
            match verdict {
                Verdict::Continue => {}
                Verdict::Discard => return Verdict::Discard,
                Verdict::DiscardSendError { code, pointer } => {
                    return Verdict::DiscardSendError {
                        code,
                        pointer: pointer + (IPV6_HEADER_LEN + 2 + start) as u32,
                    };
                }
            }
        }
        Verdict::Continue
    }
}

// The tests build on the stack's own test helpers, which need these.
#[cfg(all(
    test,
    feature = "medium-ethernet",
    feature = "medium-ip",
    feature = "ipv4",
    feature = "raw-ethernet",
    feature = "raw-ip",
    feature = "udp",
    feature = "tcp"
))]
mod tests;
