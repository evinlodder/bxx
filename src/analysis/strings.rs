//! Printable-string extraction (ASCII + optional UTF-16LE), à la `strings(1)`.

/// Cap on returned strings, to bound memory and render cost on huge files.
pub const MAX_STRINGS: usize = 50_000;

fn is_print(b: u8) -> bool {
    (0x20..0x7f).contains(&b)
}

/// Extract `(offset, text)` for every printable run of at least `min_len`
/// characters. With `utf16`, also finds UTF-16LE runs. Returns the list (sorted
/// by offset) and whether it was truncated at [`MAX_STRINGS`].
pub fn extract(data: &[u8], min_len: usize, utf16: bool) -> (Vec<(u64, String)>, bool) {
    let min_len = min_len.max(1);
    let n = data.len();
    let mut out: Vec<(u64, String)> = Vec::new();

    let mut i = 0;
    while i < n {
        if is_print(data[i]) {
            let start = i;
            let mut s = String::new();
            while i < n && is_print(data[i]) {
                s.push(data[i] as char);
                i += 1;
            }
            if s.len() >= min_len {
                out.push((start as u64, s));
                if out.len() >= MAX_STRINGS {
                    return (out, true);
                }
            }
        } else {
            i += 1;
        }
    }

    if utf16 {
        let mut i = 0;
        while i + 1 < n {
            if is_print(data[i]) && data[i + 1] == 0 {
                let start = i;
                let mut s = String::new();
                while i + 1 < n && is_print(data[i]) && data[i + 1] == 0 {
                    s.push(data[i] as char);
                    i += 2;
                }
                if s.len() >= min_len {
                    out.push((start as u64, s));
                    if out.len() >= MAX_STRINGS {
                        break;
                    }
                }
            } else {
                i += 1;
            }
        }
        out.sort_by_key(|(o, _)| *o);
    }

    let trunc = out.len() >= MAX_STRINGS;
    (out, trunc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_runs_only_above_min() {
        let data = b"\x00hello\x00ab\x00world!\x00";
        let (v, trunc) = extract(data, 4, false);
        assert!(!trunc);
        assert_eq!(v[0], (1, "hello".to_string()));
        assert_eq!(v[1], (10, "world!".to_string()));
        assert_eq!(v.len(), 2); // "ab" is too short
    }

    #[test]
    fn utf16_detected_when_requested() {
        let mut data = vec![0u8];
        for c in b"PATH" {
            data.push(*c);
            data.push(0);
        }
        let (v, _) = extract(&data, 4, true);
        assert!(v.iter().any(|(o, s)| *o == 1 && s.starts_with("PATH")));
    }
}
