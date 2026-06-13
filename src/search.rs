//! Byte pattern search with `??` wildcards, plus ASCII / UTF-16LE string search.

use crate::buffer::FileBuffer;

/// One pattern element: a concrete byte or a wildcard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pat {
    Byte(u8),
    Any,
}

#[derive(Debug, Clone, Default)]
pub struct SearchState {
    /// Last query as typed, for the status line.
    pub query: String,
    pub hits: Vec<(u64, u64)>, // (start, end)
    pub current: usize,
}

impl SearchState {
    pub fn next(&mut self, from: u64) -> Option<(u64, u64)> {
        if self.hits.is_empty() {
            return None;
        }
        // wraps to the first hit when nothing follows `from`
        let idx = self.hits.iter().position(|&(s, _)| s > from).unwrap_or(0);
        self.current = idx;
        Some(self.hits[idx])
    }

    pub fn prev(&mut self, from: u64) -> Option<(u64, u64)> {
        if self.hits.is_empty() {
            return None;
        }
        let idx = match self.hits.iter().rposition(|&(s, _)| s < from) {
            Some(i) => i,
            None => self.hits.len() - 1, // wrap
        };
        self.current = idx;
        Some(self.hits[idx])
    }

    pub fn hit_at(&self, offset: u64) -> bool {
        // hits are sorted by start; binary search the candidate then check range
        let idx = self.hits.partition_point(|&(s, _)| s <= offset);
        idx > 0 && offset < self.hits[idx - 1].1
    }
}

/// Parse `"xx xx ?? xx"` (whitespace-separated hex bytes, `??` wildcard).
/// Also accepts run-together hex like `dead??ef`.
pub fn parse_hex_pattern(input: &str) -> Result<Vec<Pat>, String> {
    let mut pats = Vec::new();
    for tok in input.split_whitespace() {
        if tok.len() % 2 != 0 {
            return Err(format!("odd-length hex token '{tok}'"));
        }
        let chars: Vec<char> = tok.chars().collect();
        for pair in chars.chunks(2) {
            let s: String = pair.iter().collect();
            if s == "??" {
                pats.push(Pat::Any);
            } else {
                let b = u8::from_str_radix(&s, 16)
                    .map_err(|_| format!("bad hex byte '{s}' in '{tok}'"))?;
                pats.push(Pat::Byte(b));
            }
        }
    }
    if pats.is_empty() {
        return Err("empty pattern".into());
    }
    Ok(pats)
}

/// Search query: `/de ad ?? ef` = hex pattern, `/"text"` = string search
/// (matches both ASCII and UTF-16LE encodings of the text).
pub fn run_search(buf: &FileBuffer, input: &str) -> Result<SearchState, String> {
    let input = input.trim();
    let mut state = SearchState {
        query: input.to_string(),
        ..Default::default()
    };
    if let Some(text) = input.strip_prefix('"') {
        let text = text.strip_suffix('"').unwrap_or(text);
        if text.is_empty() {
            return Err("empty string query".into());
        }
        let ascii: Vec<Pat> = text.bytes().map(Pat::Byte).collect();
        let utf16: Vec<Pat> = text
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .map(Pat::Byte)
            .collect();
        let mut hits = find_all(buf.raw(), buf, &ascii);
        hits.extend(find_all(buf.raw(), buf, &utf16));
        hits.sort_unstable();
        hits.dedup();
        state.hits = hits;
    } else {
        let pats = parse_hex_pattern(input)?;
        state.hits = find_all(buf.raw(), buf, &pats);
    }
    Ok(state)
}

/// Find every occurrence of a concrete byte sequence (overlay-aware). Used for
/// cross-reference scans (e.g. "find pointers equal to this offset").
pub fn find_bytes(buf: &FileBuffer, needle: &[u8]) -> Vec<(u64, u64)> {
    if needle.is_empty() {
        return Vec::new();
    }
    let pats: Vec<Pat> = needle.iter().map(|&b| Pat::Byte(b)).collect();
    find_all(buf.raw(), buf, &pats)
}

/// Scan with overlay applied. The raw mmap slice is the fast path; overlay
/// bytes are patched into a window copy only around edited offsets — but since
/// overlays are sparse and scans must see edits, we simply re-check candidate
/// windows through the buffer when any overlay exists.
fn find_all(raw: &[u8], buf: &FileBuffer, pat: &[Pat]) -> Vec<(u64, u64)> {
    let n = pat.len();
    if raw.len() < n {
        return Vec::new();
    }
    let dirty = buf.has_unsaved_changes();
    let mut hits = Vec::new();
    // First concrete byte for a cheap skip-scan.
    let anchor = pat.iter().position(|p| matches!(p, Pat::Byte(_)));
    'outer: for start in 0..=(raw.len() - n) {
        if let Some(a) = anchor
            && !dirty
            && let Pat::Byte(b) = pat[a]
            && raw[start + a] != b
        {
            continue;
        }
        for (i, p) in pat.iter().enumerate() {
            let actual = if dirty {
                buf.get((start + i) as u64).unwrap()
            } else {
                raw[start + i]
            };
            match p {
                Pat::Byte(b) if *b != actual => continue 'outer,
                _ => {}
            }
        }
        hits.push((start as u64, (start + n) as u64));
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn fixture(bytes: &[u8], tag: &str) -> FileBuffer {
        let p = std::env::temp_dir().join(format!("bx-searchtest-{tag}-{}", std::process::id()));
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(bytes).unwrap();
        FileBuffer::open(&p).unwrap()
    }

    #[test]
    fn parse_patterns() {
        assert_eq!(
            parse_hex_pattern("de ad ?? ef").unwrap(),
            vec![Pat::Byte(0xDE), Pat::Byte(0xAD), Pat::Any, Pat::Byte(0xEF)]
        );
        assert_eq!(
            parse_hex_pattern("dead??ef").unwrap(),
            vec![Pat::Byte(0xDE), Pat::Byte(0xAD), Pat::Any, Pat::Byte(0xEF)]
        );
        assert!(parse_hex_pattern("d e").is_err());
        assert!(parse_hex_pattern("zz").is_err());
        assert!(parse_hex_pattern("").is_err());
    }

    #[test]
    fn wildcard_search() {
        let buf = fixture(
            &[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xDE, 0xAD, 0xFF, 0xEF],
            "wild",
        );
        let s = run_search(&buf, "de ad ?? ef").unwrap();
        assert_eq!(s.hits, vec![(0, 4), (5, 9)]);
    }

    #[test]
    fn all_wildcards_matches_everywhere() {
        let buf = fixture(&[1, 2, 3], "anyany");
        let s = run_search(&buf, "?? ??").unwrap();
        assert_eq!(s.hits.len(), 2);
    }

    #[test]
    fn string_search_ascii_and_utf16() {
        let mut data = b"xxHIxx".to_vec();
        data.extend(b"H\0I\0"); // UTF-16LE "HI" at offset 6
        let buf = fixture(&data, "str");
        let s = run_search(&buf, "\"HI\"").unwrap();
        assert_eq!(s.hits, vec![(2, 4), (6, 10)]);
    }

    #[test]
    fn search_sees_overlay_edits() {
        let mut buf = fixture(&[0, 0, 0, 0], "overlay");
        let s = run_search(&buf, "aa").unwrap();
        assert!(s.hits.is_empty());
        buf.set(2, 0xAA);
        let s = run_search(&buf, "aa").unwrap();
        assert_eq!(s.hits, vec![(2, 3)]);
    }

    #[test]
    fn next_prev_wrap() {
        let mut s = SearchState {
            hits: vec![(2, 3), (8, 9)],
            ..Default::default()
        };
        assert_eq!(s.next(0), Some((2, 3)));
        assert_eq!(s.next(2), Some((8, 9)));
        assert_eq!(s.next(8), Some((2, 3))); // wrap
        assert_eq!(s.prev(2), Some((8, 9))); // wrap back
        assert!(s.hit_at(8));
        assert!(!s.hit_at(9));
    }
}
