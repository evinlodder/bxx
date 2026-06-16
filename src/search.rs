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

/// Search query:
/// - `de ad ?? ef` — hex pattern with `??` wildcards
/// - `"text"` — string (ASCII **and** UTF-16LE), case-sensitive
/// - `i"text"` — case-insensitive ASCII string
/// - `re:pattern` — regex over bytes (requires the `regex` build feature)
pub fn run_search(buf: &FileBuffer, input: &str) -> Result<SearchState, String> {
    let input = input.trim();
    let mut state = SearchState {
        query: input.to_string(),
        ..Default::default()
    };
    if let Some(rest) = input.strip_prefix("re:") {
        state.hits = find_regex(buf, rest)?;
    } else if let Some(text) = input
        .strip_prefix('i')
        .and_then(|r| r.strip_prefix('"'))
    {
        let text = text.strip_suffix('"').unwrap_or(text);
        if text.is_empty() {
            return Err("empty string query".into());
        }
        state.hits = find_string_ci(buf, text);
    } else if let Some(text) = input.strip_prefix('"') {
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

/// Case-insensitive ASCII string search (overlay-aware).
fn find_string_ci(buf: &FileBuffer, text: &str) -> Vec<(u64, u64)> {
    let needle: Vec<u8> = text.bytes().map(|b| b.to_ascii_lowercase()).collect();
    let n = needle.len();
    let raw = buf.raw();
    let len = raw.len();
    if n == 0 || len < n {
        return Vec::new();
    }
    let dirty = buf.has_unsaved_changes();
    let mut hits = Vec::new();
    for start in 0..=(len - n) {
        let ok = needle.iter().enumerate().all(|(i, &nb)| {
            let b = if dirty {
                buf.get((start + i) as u64).unwrap_or(0)
            } else {
                raw[start + i]
            };
            b.to_ascii_lowercase() == nb
        });
        if ok {
            hits.push((start as u64, (start + n) as u64));
        }
    }
    hits
}

#[cfg(feature = "regex")]
fn find_regex(buf: &FileBuffer, pattern: &str) -> Result<Vec<(u64, u64)>, String> {
    let re = regex::bytes::Regex::new(pattern).map_err(|e| format!("regex: {e}"))?;
    let owned;
    let data: &[u8] = if buf.has_unsaved_changes() {
        owned = buf.get_range(0, buf.len() as usize);
        &owned
    } else {
        buf.raw()
    };
    Ok(re
        .find_iter(data)
        .map(|m| (m.start() as u64, m.end() as u64))
        .collect())
}

#[cfg(not(feature = "regex"))]
fn find_regex(_buf: &FileBuffer, _pattern: &str) -> Result<Vec<(u64, u64)>, String> {
    Err("regex search not built in (rebuild with --features regex)".into())
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

/// Scan for every match of `pat`, overlay-aware.
///
/// Uses Boyer-Moore-Horspool with a bad-character skip table so it advances
/// several bytes per step instead of one. Wildcards are handled by aligning on
/// the pattern's concrete tail: trailing `??` are stripped (and re-added to the
/// match length), and the skip table only trusts the run of concrete bytes
/// after the last interior wildcard — so we never skip past a possible match.
fn find_all(raw: &[u8], buf: &FileBuffer, pat: &[Pat]) -> Vec<(u64, u64)> {
    let n = pat.len();
    let len = raw.len();
    if n == 0 || len < n {
        return Vec::new();
    }
    let dirty = buf.has_unsaved_changes();
    // Reading a byte through the overlay only when there are unsaved edits.
    let at = |i: usize| -> u8 {
        if dirty {
            buf.get(i as u64).unwrap_or(0)
        } else {
            raw[i]
        }
    };

    // Strip trailing wildcards: they always match, so search the concrete-ended
    // core and extend each hit by `trail` bytes.
    let trail = pat.iter().rev().take_while(|p| matches!(p, Pat::Any)).count();
    let core = &pat[..n - trail];
    let m = core.len();
    let mut hits = Vec::new();

    // Degenerate: pattern is all wildcards — every aligned window matches.
    if m == 0 {
        for start in 0..=(len - n) {
            hits.push((start as u64, (start + n) as u64));
        }
        return hits;
    }

    // Build the skip table over the trusted concrete suffix of `core`.
    let last_wild = core.iter().rposition(|p| matches!(p, Pat::Any));
    let suffix_lo = last_wild.map(|w| w + 1).unwrap_or(0);
    let safe = (m - suffix_lo) as u32; // max safe shift (length of concrete tail)
    let mut skip = [safe; 256];
    for (j, p) in core.iter().enumerate().take(m - 1).skip(suffix_lo) {
        if let Pat::Byte(b) = p {
            skip[*b as usize] = (m - 1 - j) as u32;
        }
    }

    let matches_at = |start: usize| -> bool {
        core.iter().enumerate().all(|(i, p)| match p {
            Pat::Byte(b) => *b == at(start + i),
            Pat::Any => true,
        })
    };

    let mut start = 0usize;
    while start + m <= len {
        if matches_at(start) && start + n <= len {
            hits.push((start as u64, (start + n) as u64));
        }
        let c = at(start + m - 1);
        start += skip[c as usize].max(1) as usize;
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

    #[test]
    fn case_insensitive_string() {
        let buf = fixture(b"xxABCyyabcZZAbC", "ci");
        let s = run_search(&buf, "i\"abc\"").unwrap();
        assert_eq!(s.hits, vec![(2, 5), (7, 10), (12, 15)]);
    }

    #[cfg(feature = "regex")]
    #[test]
    fn regex_search_when_enabled() {
        let buf = fixture(b"a12b345c", "re");
        let s = run_search(&buf, "re:[0-9]+").unwrap();
        assert_eq!(s.hits, vec![(1, 3), (4, 7)]);
    }

    #[cfg(not(feature = "regex"))]
    #[test]
    fn regex_errors_when_disabled() {
        let buf = fixture(b"abc", "nore");
        assert!(run_search(&buf, "re:abc").unwrap_err().contains("regex"));
    }

    #[test]
    fn finds_overlapping_matches() {
        let buf = fixture(b"aaaa", "overlap");
        let s = run_search(&buf, "61 61").unwrap(); // "aa"
        assert_eq!(s.hits, vec![(0, 2), (1, 3), (2, 4)]);
    }

    #[test]
    fn trailing_and_leading_wildcards() {
        let buf = fixture(&[0xAB, 0x01, 0x02, 0xAB, 0x99, 0x02], "tlw");
        // trailing wildcard: "ab ??" matches at 0 and 3
        assert_eq!(run_search(&buf, "ab ??").unwrap().hits, vec![(0, 2), (3, 5)]);
        // leading wildcard: "?? 02" matches at (1,3) and (4,6)
        assert_eq!(run_search(&buf, "?? 02").unwrap().hits, vec![(1, 3), (4, 6)]);
    }

    /// Brute-force reference, to cross-check Horspool on random data.
    fn brute(data: &[u8], pat: &[Pat]) -> Vec<(u64, u64)> {
        let n = pat.len();
        let mut hits = Vec::new();
        if n == 0 || data.len() < n {
            return hits;
        }
        for start in 0..=(data.len() - n) {
            let ok = pat.iter().enumerate().all(|(i, p)| match p {
                Pat::Byte(b) => *b == data[start + i],
                Pat::Any => true,
            });
            if ok {
                hits.push((start as u64, (start + n) as u64));
            }
        }
        hits
    }

    #[test]
    fn horspool_matches_brute_force_random() {
        // deterministic LCG so the test is reproducible
        let mut state = 0x1234_5678u64;
        let mut rng = || {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (state >> 33) as u8
        };
        // small alphabet so matches actually occur
        let data: Vec<u8> = (0..4096).map(|_| rng() % 5).collect();
        let buf = fixture(&data, "rand");

        let patterns = [
            "00", "01 02", "02 02 02", "?? 01", "03 ?? 03", "01 02 ??", "?? ?? 04",
            "04 04 04 04", "00 ?? 00 ?? 00",
        ];
        for p in patterns {
            let pat = parse_hex_pattern(p).unwrap();
            let got = run_search(&buf, p).unwrap().hits;
            assert_eq!(got, brute(&data, &pat), "pattern {p}");
        }
    }

    // `cargo test --release -- --ignored --nocapture bench_large_search`
    #[test]
    #[ignore]
    fn bench_large_search() {
        let n = 256 * 1024 * 1024;
        let mut data = vec![0u8; n];
        for i in (0..n).step_by(4096) {
            data[i] = 0xAB; // some anchor noise to defeat trivial skips
        }
        data[n - 8..].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE]);
        let buf = fixture(&data, "bench");
        let t = std::time::Instant::now();
        let s = run_search(&buf, "de ad be ef ?? fe ba be").unwrap();
        eprintln!("256MB search: {:?}, {} hit(s)", t.elapsed(), s.hits.len());
        assert_eq!(s.hits, vec![((n - 8) as u64, n as u64)]);
    }
}
