//! The tags the stack puts on the TCP segments it sends, so that a driver's
//! report of a segment lost before it left the link finds its socket.

use crate::wire::TcpSeqNumber;

/// How many of the latest segments' tags are kept. A report for an older one is
/// ignored, and its loss is left to TCP's own recovery.
const LOSS_TAG_COUNT: usize = 16;

#[derive(Debug, Clone, Copy)]
struct Tag {
    id: u32,
    socket: usize,
    seq: TcpSeqNumber,
}

/// The latest segments' tags, each in the slot of its ID: a later segment takes
/// an older one's slot.
#[derive(Debug)]
pub(crate) struct LossTags {
    tags: [Option<Tag>; LOSS_TAG_COUNT],
    next_id: u32,
}

impl LossTags {
    pub(crate) const fn new() -> Self {
        Self {
            tags: [None; LOSS_TAG_COUNT],
            next_id: 0,
        }
    }

    /// Tag the segment that starts at `seq` from the socket at `socket` in the
    /// socket slab, and return its ID.
    pub(crate) fn tag(&mut self, socket: usize, seq: TcpSeqNumber) -> u32 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.tags[Self::slot(id)] = Some(Tag { id, socket, seq });
        id
    }

    /// The socket and sequence number of the segment with ID `id`, if it's still
    /// known. It is forgotten, so that it's reported at most once.
    pub(crate) fn take(&mut self, id: u32) -> Option<(usize, TcpSeqNumber)> {
        let slot = &mut self.tags[Self::slot(id)];
        match *slot {
            Some(tag) if tag.id == id => {
                *slot = None;
                Some((tag.socket, tag.seq))
            }
            _ => None,
        }
    }

    fn slot(id: u32) -> usize {
        id as usize % LOSS_TAG_COUNT
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_tag_taken_once() {
        let mut tags = LossTags::new();
        let id = tags.tag(3, TcpSeqNumber(100));
        assert_eq!(tags.take(id), Some((3, TcpSeqNumber(100))));
        assert_eq!(tags.take(id), None);
    }

    #[test]
    fn test_later_tag_takes_older_slot() {
        let mut tags = LossTags::new();
        let first = tags.tag(0, TcpSeqNumber(0));
        for seq in 1..=LOSS_TAG_COUNT {
            tags.tag(0, TcpSeqNumber(seq as i32));
        }
        assert_eq!(tags.take(first), None);
        assert_eq!(tags.take(first + 1), Some((0, TcpSeqNumber(1))));
    }
}
