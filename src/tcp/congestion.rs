use crate::time::Instant;

use super::RttEstimator;

#[cfg(not(any(feature = "tcp-reno", feature = "tcp-cubic")))]
pub(super) mod no_control;

#[cfg(feature = "tcp-cubic")]
pub(super) mod cubic;

#[cfg(feature = "tcp-reno")]
pub(super) mod reno;

/// The initial congestion window for a sender's maximum segment size `mss`
/// (RFC 5681 § 3.1): four segments up to 1095 bytes, three up to 2190, and two
/// above.
#[allow(unused)] // unused without a congestion controller
pub(super) fn initial_window(mss: usize) -> usize {
    match mss {
        0..=1095 => 4 * mss,
        1096..=2190 => 3 * mss,
        _ => 2 * mss,
    }
}

#[allow(unused_variables)]
pub(super) trait Controller {
    /// Returns the number of bytes that can be sent.
    fn window(&self) -> usize;

    /// Set the remote window size.
    fn set_remote_window(&mut self, remote_window: usize) {}

    fn on_ack(&mut self, now: Instant, len: usize, in_flight: usize, rtt: &RttEstimator) {}

    /// Fired on each duplicate ack received, after `on_loss` has been called.
    fn on_dup_ack(&mut self, now: Instant, len: usize, in_flight: usize) {}

    /// Fired on a retransmission timeout.
    fn on_rto(&mut self, now: Instant, in_flight: usize) {}

    /// Fired after an inferred loss via three duplicate acks.
    fn on_loss(&mut self, now: Instant, in_flight: usize) {}

    fn pre_transmit(&mut self, now: Instant) {}

    fn post_transmit(&mut self, now: Instant, len: usize) {}

    /// Set the maximum segment size, when a connection is set up. The window
    /// starts over at [`initial_window`] for it.
    fn set_mss(&mut self, mss: usize) {}
}

/// The congestion controller this build uses, picked by the `tcp-reno` and
/// `tcp-cubic` cargo features.
#[cfg(not(any(feature = "tcp-reno", feature = "tcp-cubic")))]
pub(super) type Congestion = no_control::NoControl;

#[cfg(feature = "tcp-reno")]
pub(super) type Congestion = reno::Reno;

#[cfg(feature = "tcp-cubic")]
pub(super) type Congestion = cubic::Cubic;

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_initial_window() {
        // RFC 5681 § 3.1.
        assert_eq!(initial_window(40), 160);
        assert_eq!(initial_window(536), 2144);
        assert_eq!(initial_window(1095), 4380);
        assert_eq!(initial_window(1460), 4380);
        assert_eq!(initial_window(2190), 6570);
        assert_eq!(initial_window(4000), 8000);
    }

    #[test]
    fn test_controller_starts_at_initial_window() {
        // A connection's window starts at the initial window for its MSS, once
        // it is known, as with the 40-byte segments of 6LoWPAN links.
        let mut controller = Congestion::new();
        controller.set_mss(40);
        #[cfg(any(feature = "tcp-reno", feature = "tcp-cubic"))]
        assert_eq!(controller.window(), 160);
        controller.set_mss(1460);
        #[cfg(any(feature = "tcp-reno", feature = "tcp-cubic"))]
        assert_eq!(controller.window(), 4380);
    }
}
