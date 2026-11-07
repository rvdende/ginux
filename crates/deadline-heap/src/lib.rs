#![forbid(unsafe_code)]
//! The earliest of many deadlines: a binary min-heap of `(deadline, key)`
//! entries whose entries are checked, not removed, when what they stand
//! for changes.
//!
//! The kernel marks a process asleep until a deadline many times over (each
//! round of a wait marks it again), and the mark goes when the process is
//! dispatched, woken or ends, in places that have no business knowing about
//! a heap. So an entry is pushed for every mark and nothing is ever taken
//! out by those places; instead [`DeadlineHeap::earliest`] asks the caller
//! whether the entry at the top still holds and drops it if not, until one
//! does. Asking for the earliest deadline costs the stale entries ahead of
//! it, each dropped once, and a logarithmic step each. [`DeadlineHeap::retain`]
//! drops the stale entries everywhere, for a heap that grows past a bound
//! without being asked (marks with no idle CPU to look).
//!
//! Every growth is fallible: the kernel reports an allocation failure
//! instead of panicking. This is pure bookkeeping, tested on the host.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;

/// The heap ran out of memory for another entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutOfMemory;

/// A min-heap of `(deadline, key)` entries ordered by deadline.
#[derive(Debug, Default)]
pub struct DeadlineHeap<K> {
    entries: Vec<(u64, K)>,
}

impl<K: Copy> DeadlineHeap<K> {
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Entries held, stale ones included.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Adds `key` due at `deadline`.
    pub fn push(&mut self, deadline: u64, key: K) -> Result<(), OutOfMemory> {
        self.entries.try_reserve(1).map_err(|_| OutOfMemory)?;
        self.entries.push((deadline, key));
        self.sift_up(self.entries.len() - 1);
        Ok(())
    }

    /// The earliest entry `holds` says still stands, `holds(key, deadline)`
    /// being asked of the earliest entries in turn: those it rejects are
    /// dropped. None when no entry holds.
    pub fn earliest(&mut self, mut holds: impl FnMut(K, u64) -> bool) -> Option<(u64, K)> {
        while let Some(&(deadline, key)) = self.entries.first() {
            if holds(key, deadline) {
                return Some((deadline, key));
            }
            self.pop();
        }
        None
    }

    /// Takes the earliest entry out, whether it holds or not.
    pub fn pop(&mut self) -> Option<(u64, K)> {
        if self.entries.is_empty() {
            return None;
        }
        let last = self.entries.len() - 1;
        self.entries.swap(0, last);
        let earliest = self.entries.pop();
        if !self.entries.is_empty() {
            self.sift_down(0);
        }
        earliest
    }

    /// Keeps only the entries `holds` says still stand.
    pub fn retain(&mut self, mut holds: impl FnMut(K, u64) -> bool) {
        self.entries.retain(|&(deadline, key)| holds(key, deadline));
        // Heapify bottom-up: each parent from the last one down.
        for index in (0..self.entries.len() / 2).rev() {
            self.sift_down(index);
        }
    }

    /// Drops every entry.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    fn sift_up(&mut self, mut index: usize) {
        while index > 0 {
            let parent = (index - 1) / 2;
            if self.entries[parent].0 <= self.entries[index].0 {
                break;
            }
            self.entries.swap(parent, index);
            index = parent;
        }
    }

    fn sift_down(&mut self, mut index: usize) {
        loop {
            let left = 2 * index + 1;
            let right = left + 1;
            let mut smallest = index;
            if left < self.entries.len() && self.entries[left].0 < self.entries[smallest].0 {
                smallest = left;
            }
            if right < self.entries.len() && self.entries[right].0 < self.entries[smallest].0 {
                smallest = right;
            }
            if smallest == index {
                return;
            }
            self.entries.swap(index, smallest);
            index = smallest;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    extern crate std;
    use std::collections::BTreeMap;

    #[test]
    fn earliest_is_the_smallest_deadline() {
        let mut heap = DeadlineHeap::new();
        for (deadline, key) in [(50, 'a'), (10, 'b'), (30, 'c'), (20, 'd'), (40, 'e')] {
            heap.push(deadline, key).unwrap();
        }
        assert_eq!(heap.earliest(|_, _| true), Some((10, 'b')));
        let mut order = vec![];
        while let Some((deadline, _)) = heap.pop() {
            order.push(deadline);
        }
        assert_eq!(order, [10, 20, 30, 40, 50]);
    }

    #[test]
    fn stale_entries_ahead_are_dropped() {
        let mut heap = DeadlineHeap::new();
        heap.push(10, 1).unwrap();
        heap.push(20, 2).unwrap();
        heap.push(30, 3).unwrap();
        // Key 1 was dispatched and key 2 marked again for later.
        assert_eq!(heap.earliest(|key, _| key == 3), Some((30, 3)));
        assert_eq!(heap.len(), 1);
    }

    #[test]
    fn none_when_nothing_holds() {
        let mut heap = DeadlineHeap::new();
        heap.push(10, 1).unwrap();
        heap.push(5, 2).unwrap();
        assert_eq!(heap.earliest(|_, _| false), None);
        assert!(heap.is_empty());
        assert_eq!(DeadlineHeap::<u32>::new().earliest(|_, _| true), None);
    }

    #[test]
    fn a_key_marked_again_holds_only_at_its_latest_deadline() {
        // The kernel's use: each mark pushes; the current mark is the only
        // entry that holds.
        let mut heap = DeadlineHeap::new();
        let mut current = BTreeMap::new();
        for (deadline, pid) in [(100, 7), (40, 7), (70, 7), (60, 8)] {
            heap.push(deadline, pid).unwrap();
            current.insert(pid, deadline);
        }
        let holds = |pid, deadline| current.get(&pid) == Some(&deadline);
        assert_eq!(heap.earliest(holds), Some((60, 8)));
        current.remove(&8);
        let holds = |pid, deadline| current.get(&pid) == Some(&deadline);
        assert_eq!(heap.earliest(holds), Some((70, 7)));
    }

    #[test]
    fn retain_compacts_and_keeps_the_order() {
        let mut heap = DeadlineHeap::new();
        for index in 0..1000_u64 {
            heap.push((index * 7919) % 1000, index).unwrap();
        }
        heap.retain(|key, _| key % 3 == 0);
        assert_eq!(heap.len(), 334);
        let mut last = 0;
        while let Some((deadline, key)) = heap.pop() {
            assert!(deadline >= last);
            assert_eq!(key % 3, 0);
            last = deadline;
        }
    }

    #[test]
    fn matches_a_sorted_model_under_random_use() {
        // A small deterministic generator, so the test needs no crate.
        let mut state = 0x2545_f491_4f6c_dd1d_u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut heap = DeadlineHeap::new();
        let mut model: BTreeMap<u32, u64> = BTreeMap::new();
        for _ in 0..20_000 {
            let key = (next() % 64) as u32;
            match next() % 4 {
                0 | 1 => {
                    let deadline = next() % 10_000;
                    heap.push(deadline, key).unwrap();
                    model.insert(key, deadline);
                }
                2 => {
                    model.remove(&key);
                }
                _ => {
                    let expected = model
                        .iter()
                        .map(|(key, deadline)| (*deadline, *key))
                        .min_by_key(|(deadline, _)| *deadline);
                    let found = heap.earliest(|key, deadline| model.get(&key) == Some(&deadline));
                    assert_eq!(
                        found.map(|(deadline, _)| deadline),
                        expected.map(|(d, _)| d)
                    );
                }
            }
            if heap.len() > 512 {
                heap.retain(|key, deadline| model.get(&key) == Some(&deadline));
                assert_eq!(heap.len(), model.len());
            }
        }
    }
}
