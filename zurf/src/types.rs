// SPDX-License-Identifier: LGPL-3.0-or-later

use zurf_enum_derive::TryFromU8;

// ==========================================
// Base ID and Destination Types
// ==========================================

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HomeId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NodeId(pub u16);

impl NodeId {
    pub fn is_broadcast(&self) -> bool {
        self.0 == 0xFF || self.0 == 0x0FFF
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Destination {
    Single(NodeId),
    Multicast(Vec<NodeId>),
    Broadcast,
}

// ==========================================
// RSSI & Routing Hop Types
// ==========================================

#[repr(u8)]
#[derive(TryFromU8, Debug, Clone, Copy, PartialEq, Eq)]
pub enum RssiError {
    TooLow = 0x7D,
    Saturation = 0x7E,
    NotAvailable = 0x7F,
}

pub type Rssi = Result<i8, RssiError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hop {
    pub node_id: NodeId,
    pub rssi: Rssi,
}

pub fn noise_floor_from_byte(byte: u8) -> Rssi {
    let signed_byte = byte.cast_signed();
    if (-120..=30).contains(&signed_byte) {
        Ok(signed_byte)
    } else {
        Err(RssiError::NotAvailable)
    }
}

pub fn lr_rssi_from_byte(byte: u8) -> Rssi {
    noise_floor_from_byte(byte)
}

pub fn tx_power_from_byte(byte: u8) -> Rssi {
    let signed_byte = byte.cast_signed();
    if (-100..=35).contains(&signed_byte) {
        Ok(signed_byte)
    } else {
        Err(RssiError::NotAvailable)
    }
}

impl Hop {
    pub fn rssi_from_byte(byte: u8) -> Rssi {
        match byte {
            0x7D => Err(RssiError::TooLow),
            0x7E => Err(RssiError::Saturation),
            0x7F => Err(RssiError::NotAvailable),
            _ => Ok(byte as i8),
        }
    }
}

// ==========================================
// Channel & Speed Types
// ==========================================

#[repr(u8)]
#[derive(TryFromU8, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    Mesh1 = 0,
    Mesh2 = 1,
    Mesh3 = 2,
    LongRangeA = 3,
    LongRangeB = 4,
}

impl Channel {
    pub fn is_long_range(&self) -> bool {
        matches!(self, Channel::LongRangeA | Channel::LongRangeB)
    }
}

#[repr(u8)]
#[derive(TryFromU8, Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataSpeed {
    Mesh9600 = 0,
    Mesh40k = 1,
    Mesh100k = 2,
    LongRange100k = 3,
}

impl DataSpeed {
    pub fn is_long_range(&self) -> bool {
        matches!(self, DataSpeed::LongRange100k)
    }
}

// ==========================================
// Parsing Support Types
// ==========================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    Empty,
    Incomplete,
    Invalid,
}

pub type ParseResult<'a, T> = std::result::Result<(T, &'a [u8]), ParseError>;

// ==========================================
// Utility Structures
// ==========================================

/**
 * Very small, fixed size queue to fit on the stack. Do not use with large sizes. Not Thread-safe
 */
pub struct FixedKeyValueQueue<const N: usize, K, V> {
    buffer: [Option<(K, V)>; N],
    head: usize,
    tail: usize,
    full: bool,
}

impl<const N: usize, K, V> std::default::Default for FixedKeyValueQueue<N, K, V> {
    fn default() -> Self {
        const {
            assert!(
                N > 0,
                "FixedKeyValueQueue capacity N must be greater than 0"
            );
        }
        Self {
            buffer: [const { None }; N],
            head: 0,
            tail: 0,
            full: false,
        }
    }
}

/**
 * This does not check for duplicates, letting you 'refresh' an entry. This is helpful for receivers entropy,
 * in case multiple S2 syncs are necessary. Note that this does not delete the old entry, meaning the capacity
 * is still reduced
 */
impl<const N: usize, K: PartialEq + std::fmt::Debug, V> FixedKeyValueQueue<N, K, V> {
    pub fn push(&mut self, key: K, value: V) -> Option<(K, V)> {
        let evicted = if self.full { self.pop() } else { None };
        let item = (key, value);
        let next = (self.tail + 1) % N;
        self.full = next == self.head;
        self.buffer[self.tail] = Some(item);
        self.tail = next;
        evicted
    }

    pub fn pop(&mut self) -> Option<(K, V)> {
        if self.is_empty() {
            return None;
        }
        let item = self.buffer[self.head].take();
        self.head = (self.head + 1) % N;
        self.full = false;
        item
    }

    pub fn len(&self) -> usize {
        if self.full {
            N
        } else {
            (self.tail + N - self.head) % N
        }
    }

    pub fn is_empty(&self) -> bool {
        (self.head == self.tail) && !self.full
    }

    pub fn get(&self, key: &K) -> Option<&V> {
        if self.is_empty() {
            return None;
        }
        for i in 0..self.len() {
            // Start with the most recently inserted item, in case of duplicates
            let index = (self.tail + N - 1 - i) % N;
            if let Some((k, v)) = &self.buffer[index]
                && k == key
            {
                return Some(v);
            }
        }
        None
    }
}

// ==========================================
// Tests
// ==========================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_push_pop_fifo() {
        let mut queue: FixedKeyValueQueue<4, &'static str, i32> = FixedKeyValueQueue::default();
        assert!(queue.is_empty());
        assert_eq!(queue.len(), 0);

        queue.push("one", 1);
        queue.push("two", 2);
        assert_eq!(queue.len(), 2);
        assert!(!queue.is_empty());

        assert_eq!(queue.pop(), Some(("one", 1)));
        assert_eq!(queue.pop(), Some(("two", 2)));
        assert!(queue.is_empty());
    }

    #[test]
    fn test_queue_full() {
        let mut queue: FixedKeyValueQueue<3, &'static str, i32> = FixedKeyValueQueue::default();

        assert!(queue.push("one", 1).is_none());
        assert!(queue.push("two", 2).is_none());
        assert!(queue.push("three", 3).is_none());

        assert_eq!(queue.push("buckle my shoe", 4), Some(("one", 1)));
    }

    #[test]
    fn test_get_lookup() {
        let mut queue: FixedKeyValueQueue<4, &'static str, i32> = FixedKeyValueQueue::default();
        queue.push("one", 1);
        queue.push("two", 2);

        assert_eq!(queue.get(&"one"), Some(&1));
        assert_eq!(queue.get(&"two"), Some(&2));
        assert_eq!(queue.get(&"three"), None);
    }

    #[test]
    fn test_circular_wrap_around_get() {
        let mut queue: FixedKeyValueQueue<4, i32, &'static str> = FixedKeyValueQueue::default();

        queue.push(10, "ten");
        queue.push(20, "twenty");
        queue.push(30, "thirty");
        queue.push(40, "forty");

        // Pop one element (freeing slot 0)
        assert_eq!(queue.pop(), Some((10, "ten")));

        queue.push(50, "fifty");

        assert_eq!(queue.len(), 4);

        // Verify get still works for all active elements after wrap-around
        assert_eq!(queue.get(&20), Some(&"twenty"));
        assert_eq!(queue.get(&30), Some(&"thirty"));
        assert_eq!(queue.get(&40), Some(&"forty"));
        assert_eq!(queue.get(&50), Some(&"fifty"));
        assert_eq!(queue.get(&10), None);
    }

    #[test]
    fn test_capacity_one() {
        let mut queue: FixedKeyValueQueue<1, &'static str, i32> = FixedKeyValueQueue::default();
        assert!(queue.is_empty());
        assert_eq!(queue.len(), 0);

        queue.push("one", 1);
        assert_eq!(queue.len(), 1);
        assert!(!queue.is_empty());

        assert!(queue.push("two", 2) == Some(("one", 1)));

        assert_eq!(queue.pop(), Some(("two", 2)));
        assert!(queue.is_empty());
    }

    #[test]
    fn test_duplicate() {
        let mut queue: FixedKeyValueQueue<2, &'static str, i32> = FixedKeyValueQueue::default();
        assert!(queue.is_empty());
        assert_eq!(queue.len(), 0);

        queue.push("one", 1);
        assert_eq!(queue.len(), 1);
        assert!(!queue.is_empty());

        queue.push("one", 3);
        assert_eq!(queue.get(&"one"), Some(&3));
    }

    #[test]
    fn test_noise_floor_from_byte() {
        // Valid bounds [-120, 30]
        assert_eq!(noise_floor_from_byte(0).unwrap(), 0);
        assert_eq!(noise_floor_from_byte(30).unwrap(), 30);
        assert_eq!(noise_floor_from_byte(-120i8 as u8).unwrap(), -120);

        // Invalid bounds
        assert_eq!(noise_floor_from_byte(31), Err(RssiError::NotAvailable));
        assert_eq!(
            noise_floor_from_byte(-121i8 as u8),
            Err(RssiError::NotAvailable)
        );
    }

    #[test]
    fn test_lr_rssi_from_byte() {
        assert_eq!(lr_rssi_from_byte(0).unwrap(), 0);
        assert_eq!(lr_rssi_from_byte(31), Err(RssiError::NotAvailable));
    }

    #[test]
    fn test_tx_power_from_byte() {
        // Valid bounds [-100, 35]
        assert_eq!(tx_power_from_byte(0).unwrap(), 0);
        assert_eq!(tx_power_from_byte(35).unwrap(), 35);
        assert_eq!(tx_power_from_byte(-100i8 as u8).unwrap(), -100);

        // Invalid bounds
        assert_eq!(tx_power_from_byte(36), Err(RssiError::NotAvailable));
        assert_eq!(
            tx_power_from_byte(-101i8 as u8),
            Err(RssiError::NotAvailable)
        );
    }
}
