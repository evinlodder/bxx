//! Byte diff between two buffers, grouped into hunks.
//!
//! Two modes: a fast **positional** compare ([`compute`], right for in-place
//! patched images) and an **alignment-aware** diff ([`diff`]) that survives
//! inserted/deleted bytes (difflib-style matching blocks) and reports a
//! similarity score. Large inputs fall back to positional.

use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HunkKind {
    Changed,
    /// Present only in the second file (it is longer).
    Added,
    /// Present only in the first file (second is shorter).
    Removed,
}

#[derive(Debug, Clone, Copy)]
pub struct Hunk {
    pub start: u64,
    pub end: u64,
    pub kind: HunkKind,
}

/// Byte runs that differ, merging runs separated by fewer than `gap` equal
/// bytes so a sprinkle of changes reads as one hunk.
pub fn compute(a: &[u8], b: &[u8], gap: usize) -> Vec<Hunk> {
    let common = a.len().min(b.len());
    let mut hunks: Vec<Hunk> = Vec::new();
    let mut i = 0;
    while i < common {
        if a[i] != b[i] {
            let start = i;
            let mut last_diff = i;
            i += 1;
            while i < common && i - last_diff <= gap {
                if a[i] != b[i] {
                    last_diff = i;
                }
                i += 1;
            }
            hunks.push(Hunk {
                start: start as u64,
                end: (last_diff + 1) as u64,
                kind: HunkKind::Changed,
            });
            i = last_diff + 1;
        } else {
            i += 1;
        }
    }
    use std::cmp::Ordering;
    match a.len().cmp(&b.len()) {
        Ordering::Less => hunks.push(Hunk {
            start: common as u64,
            end: b.len() as u64,
            kind: HunkKind::Added,
        }),
        Ordering::Greater => hunks.push(Hunk {
            start: common as u64,
            end: a.len() as u64,
            kind: HunkKind::Removed,
        }),
        Ordering::Equal => {}
    }
    hunks
}

/// Alignment-aware diff result. `a_hunks`/`b_hunks` are in each file's own
/// coordinates; `similarity` is 0.0..=1.0; `aligned` is false when the inputs
/// were too large and the positional fallback was used.
pub struct DiffResult {
    pub a_hunks: Vec<Hunk>,
    pub b_hunks: Vec<Hunk>,
    pub similarity: f64,
    pub aligned: bool,
}

/// Per-side byte cap above which we fall back to the positional compare.
const ALIGN_CAP: usize = 2 << 20;

/// Diff `a` and `b`, tracking insertions/deletions when the inputs are small
/// enough, else a positional compare.
pub fn diff(a: &[u8], b: &[u8]) -> DiffResult {
    if a.len() > ALIGN_CAP || b.len() > ALIGN_CAP {
        let h = compute(a, b, 4);
        let common = a.len().min(b.len());
        let matched = (0..common).filter(|&i| a[i] == b[i]).count();
        let total = a.len() + b.len();
        let similarity = if total == 0 {
            1.0
        } else {
            2.0 * matched as f64 / total as f64
        };
        return DiffResult {
            a_hunks: h.clone(),
            b_hunks: h,
            similarity,
            aligned: false,
        };
    }
    let mut blocks = matching_blocks(a, b);
    let matched: usize = blocks.iter().map(|&(_, _, k)| k).sum();
    let total = a.len() + b.len();
    let similarity = if total == 0 {
        1.0
    } else {
        2.0 * matched as f64 / total as f64
    };
    blocks.push((a.len(), b.len(), 0)); // sentinel covers the trailing gap
    let (a_hunks, b_hunks) = derive_hunks(&blocks);
    DiffResult {
        a_hunks,
        b_hunks,
        similarity,
        aligned: true,
    }
}

/// Matching blocks `(i, j, size)` s.t. `a[i..i+size] == b[j..j+size]`,
/// difflib's recursive longest-match with the autojunk heuristic for the
/// dense byte alphabet.
fn matching_blocks(a: &[u8], b: &[u8]) -> Vec<(usize, usize, usize)> {
    let n = b.len();
    let mut b2j: HashMap<u8, Vec<usize>> = HashMap::new();
    for (j, &byte) in b.iter().enumerate() {
        b2j.entry(byte).or_default().push(j);
    }
    if n >= 200 {
        let popular = n / 100 + 1;
        b2j.retain(|_, idxs| idxs.len() <= popular);
    }

    let mut queue = vec![(0usize, a.len(), 0usize, b.len())];
    let mut blocks = Vec::new();
    while let Some((alo, ahi, blo, bhi)) = queue.pop() {
        let (i, j, k) = longest_match(a, &b2j, alo, ahi, blo, bhi);
        if k > 0 {
            blocks.push((i, j, k));
            if alo < i && blo < j {
                queue.push((alo, i, blo, j));
            }
            if i + k < ahi && j + k < bhi {
                queue.push((i + k, ahi, j + k, bhi));
            }
        }
    }
    blocks.sort_unstable();
    blocks
}

fn longest_match(
    a: &[u8],
    b2j: &HashMap<u8, Vec<usize>>,
    alo: usize,
    ahi: usize,
    blo: usize,
    bhi: usize,
) -> (usize, usize, usize) {
    let (mut besti, mut bestj, mut bestsize) = (alo, blo, 0usize);
    let mut j2len: HashMap<usize, usize> = HashMap::new();
    for (i, &byte) in a.iter().enumerate().take(ahi).skip(alo) {
        let mut newj2len: HashMap<usize, usize> = HashMap::new();
        if let Some(js) = b2j.get(&byte) {
            for &j in js {
                if j < blo {
                    continue;
                }
                if j >= bhi {
                    break;
                }
                let k = j2len.get(&j.wrapping_sub(1)).copied().unwrap_or(0) + 1;
                newj2len.insert(j, k);
                if k > bestsize {
                    besti = i + 1 - k;
                    bestj = j + 1 - k;
                    bestsize = k;
                }
            }
        }
        j2len = newj2len;
    }
    (besti, bestj, bestsize)
}

fn derive_hunks(blocks: &[(usize, usize, usize)]) -> (Vec<Hunk>, Vec<Hunk>) {
    let (mut ai, mut bj) = (0usize, 0usize);
    let (mut ah, mut bh) = (Vec::new(), Vec::new());
    for &(mi, mj, size) in blocks {
        let a_gap = mi > ai;
        let b_gap = mj > bj;
        let both = a_gap && b_gap;
        if a_gap {
            ah.push(Hunk {
                start: ai as u64,
                end: mi as u64,
                kind: if both { HunkKind::Changed } else { HunkKind::Removed },
            });
        }
        if b_gap {
            bh.push(Hunk {
                start: bj as u64,
                end: mj as u64,
                kind: if both { HunkKind::Changed } else { HunkKind::Added },
            });
        }
        ai = mi + size;
        bj = mj + size;
    }
    (ah, bh)
}

/// Hunk containing or nearest after `offset` (for n), wrapped.
pub fn next_hunk(hunks: &[Hunk], offset: u64) -> Option<&Hunk> {
    if hunks.is_empty() {
        return None;
    }
    hunks.iter().find(|h| h.start > offset).or(hunks.first())
}

pub fn prev_hunk(hunks: &[Hunk], offset: u64) -> Option<&Hunk> {
    if hunks.is_empty() {
        return None;
    }
    hunks
        .iter()
        .rev()
        .find(|h| h.start < offset)
        .or(hunks.last())
}

pub fn hunk_at(hunks: &[Hunk], offset: u64) -> Option<&Hunk> {
    let idx = hunks.partition_point(|h| h.start <= offset);
    idx.checked_sub(1)
        .map(|i| &hunks[i])
        .filter(|h| offset < h.end)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn three_hunks() {
        let a = [0u8; 32];
        let mut b = a;
        b[2] = 1;
        b[3] = 1;
        b[16] = 1;
        b[30] = 1;
        let hunks = compute(&a, &b, 3);
        assert_eq!(hunks.len(), 3);
        assert_eq!((hunks[0].start, hunks[0].end), (2, 4));
        assert_eq!((hunks[1].start, hunks[1].end), (16, 17));
        assert_eq!((hunks[2].start, hunks[2].end), (30, 31));
    }

    #[test]
    fn gap_merging() {
        let a = [0u8; 10];
        let mut b = a;
        b[2] = 1;
        b[5] = 1; // 2 equal bytes apart -> merged with gap=3
        let hunks = compute(&a, &b, 3);
        assert_eq!(hunks.len(), 1);
        assert_eq!((hunks[0].start, hunks[0].end), (2, 6));
    }

    #[test]
    fn length_mismatch() {
        let hunks = compute(&[1, 2], &[1, 2, 3, 4], 0);
        assert_eq!(hunks.len(), 1);
        assert_eq!(hunks[0].kind, HunkKind::Added);
        assert_eq!((hunks[0].start, hunks[0].end), (2, 4));
        let hunks = compute(&[1, 2, 3], &[1], 0);
        assert_eq!(hunks[0].kind, HunkKind::Removed);
    }

    #[test]
    fn aligned_diff_survives_insertion() {
        // b is a with "XYZ" inserted after position 4 — positional diff would
        // mark everything after as changed; alignment should not.
        let a = b"AAAABBBBCCCC";
        let b = b"AAAAXYZBBBBCCCC";
        let r = diff(a, b);
        assert!(r.aligned);
        // A has no removed/changed region (it's wholly contained in b)
        assert!(r.a_hunks.is_empty(), "{:?}", r.a_hunks);
        // B has one inserted run "XYZ" at offset 4..7
        assert_eq!(r.b_hunks.len(), 1);
        assert_eq!(r.b_hunks[0].kind, HunkKind::Added);
        assert_eq!((r.b_hunks[0].start, r.b_hunks[0].end), (4, 7));
        // similarity = 2*12 / (12+15)
        assert!((r.similarity - (24.0 / 27.0)).abs() < 1e-9);
    }

    #[test]
    fn aligned_identical_is_full_similarity() {
        let r = diff(b"hello world", b"hello world");
        assert_eq!(r.similarity, 1.0);
        assert!(r.a_hunks.is_empty() && r.b_hunks.is_empty());
    }

    #[test]
    fn navigation_wraps() {
        let hunks = compute(&[0u8, 0, 0, 0, 0], &[1u8, 0, 0, 0, 1], 0);
        assert_eq!(hunks.len(), 2);
        assert_eq!(next_hunk(&hunks, 0).unwrap().start, 4);
        assert_eq!(next_hunk(&hunks, 4).unwrap().start, 0); // wrap
        assert_eq!(prev_hunk(&hunks, 4).unwrap().start, 0);
        assert_eq!(prev_hunk(&hunks, 0).unwrap().start, 4); // wrap
        assert!(hunk_at(&hunks, 0).is_some());
        assert!(hunk_at(&hunks, 2).is_none());
    }
}
