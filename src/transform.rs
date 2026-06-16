//! CyberChef-style transform pipeline.
//!
//! A *recipe* is an ordered list of operation strings (e.g. `["unbase64",
//! "xor 5a", "pipe zcat"]`); data flows through each step. Built-in ops are
//! pure-Rust and dependency-free. Two escape hatches give users their own
//! transforms without recompiling bxx:
//!
//! - **named pipelines** in `~/.bxpipes` (`name = op | op | …`) compose the
//!   built-ins into reusable recipes, and
//! - **`pipe <cmd>`** streams the bytes through any external program's
//!   stdin/stdout, so a transform can be written in any language.

use std::collections::HashMap;
use std::path::PathBuf;

/// Run a whole recipe over `input`, returning the transformed bytes.
pub fn run(recipe: &[String], input: &[u8]) -> Result<Vec<u8>, String> {
    let mut data = input.to_vec();
    for (i, op) in recipe.iter().enumerate() {
        if op.trim().is_empty() {
            continue;
        }
        data = apply_op(op, &data).map_err(|e| format!("step {}: {e}", i + 1))?;
    }
    Ok(data)
}

/// Apply a single `"name args…"` operation to `data`.
pub fn apply_op(op: &str, data: &[u8]) -> Result<Vec<u8>, String> {
    let mut it = op.split_whitespace();
    let name = it.next().unwrap_or("");
    let rest: Vec<&str> = it.collect();
    match name {
        "" => Ok(data.to_vec()),
        // encodings
        "hex" => Ok(hex_encode(data)),
        "unhex" => hex_decode(data),
        "base64" | "b64" => Ok(b64_encode(data)),
        "unbase64" | "unb64" => b64_decode(data),
        "url" => Ok(url_encode(data)),
        "unurl" => url_decode(data),
        // bitwise / arithmetic
        "xor" => Ok(xor(data, &parse_key(&rest)?)),
        "add" => {
            let n = parse_byte(&rest)?;
            Ok(data.iter().map(|b| b.wrapping_add(n)).collect())
        }
        "sub" => {
            let n = parse_byte(&rest)?;
            Ok(data.iter().map(|b| b.wrapping_sub(n)).collect())
        }
        "not" => Ok(data.iter().map(|b| !b).collect()),
        "rol" => {
            let n = (parse_int(&rest)? as u32) % 8;
            Ok(data.iter().map(|b| b.rotate_left(n)).collect())
        }
        "ror" => {
            let n = (parse_int(&rest)? as u32) % 8;
            Ok(data.iter().map(|b| b.rotate_right(n)).collect())
        }
        "reverse" | "rev" => {
            let mut v = data.to_vec();
            v.reverse();
            Ok(v)
        }
        "swap16" => Ok(swap(data, 2)),
        "swap32" => Ok(swap(data, 4)),
        "swap64" => Ok(swap(data, 8)),
        // text
        "rot13" => Ok(rot13(data)),
        "upper" => Ok(data.iter().map(|b| b.to_ascii_uppercase()).collect()),
        "lower" => Ok(data.iter().map(|b| b.to_ascii_lowercase()).collect()),
        // slicing
        "take" => {
            let n = parse_int(&rest)? as usize;
            Ok(data.iter().take(n).copied().collect())
        }
        "drop" | "skip" => {
            let n = parse_int(&rest)? as usize;
            Ok(data.iter().skip(n).copied().collect())
        }
        // hashes → hex digest
        "md5" => Ok(format!("{:x}", md5::compute(data)).into_bytes()),
        "sha1" => Ok(hex_encode(&crate::analysis::checksum::sha1(data))),
        "sha256" => Ok(hex_encode(&crate::analysis::checksum::sha256(data))),
        "crc32" => Ok(format!("{:08x}", crate::analysis::checksum::crc32(data)).into_bytes()),
        // external program
        "pipe" => pipe(data, &rest.join(" ")),
        _ => Err(format!("unknown op '{name}'")),
    }
}

/// Op names for help / completion.
pub const OP_NAMES: &[&str] = &[
    "hex", "unhex", "base64", "unbase64", "url", "unurl", "xor", "add", "sub", "not", "rol", "ror",
    "reverse", "swap16", "swap32", "swap64", "rot13", "upper", "lower", "take", "drop", "md5",
    "sha1", "sha256", "crc32", "pipe",
];

// --- argument parsing --------------------------------------------------------

/// A repeating key: hex (`5a`, `dead`, `0xde 0xad`) or `"text"`.
fn parse_key(args: &[&str]) -> Result<Vec<u8>, String> {
    if args.is_empty() {
        return Err("xor: need a key, e.g. `xor 5a` or `xor \"text\"`".into());
    }
    let joined = args.join(" ");
    if let Some(t) = joined.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
        return Ok(t.as_bytes().to_vec());
    }
    let hex: String = joined
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .replace("0x", "")
        .replace("0X", "");
    if hex.is_empty() || !hex.len().is_multiple_of(2) {
        return Err(format!("xor: bad hex key '{joined}'"));
    }
    let mut key = Vec::with_capacity(hex.len() / 2);
    let b = hex.as_bytes();
    for pair in b.chunks(2) {
        key.push((hexval(pair[0])? << 4) | hexval(pair[1])?);
    }
    Ok(key)
}

fn parse_int(args: &[&str]) -> Result<i64, String> {
    let s = args.first().ok_or("missing number argument")?;
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        i64::from_str_radix(h, 16).map_err(|_| format!("bad number '{s}'"))
    } else {
        s.parse().map_err(|_| format!("bad number '{s}'"))
    }
}

fn parse_byte(args: &[&str]) -> Result<u8, String> {
    let v = parse_int(args)?;
    u8::try_from(v & 0xff).map_err(|_| "value out of range".into())
}

fn hexval(c: u8) -> Result<u8, String> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(format!("bad hex digit '{}'", c as char)),
    }
}

// --- byte ops ----------------------------------------------------------------

fn xor(data: &[u8], key: &[u8]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, b)| b ^ key[i % key.len()])
        .collect()
}

fn swap(data: &[u8], w: usize) -> Vec<u8> {
    let mut out = data.to_vec();
    for chunk in out.chunks_mut(w) {
        if chunk.len() == w {
            chunk.reverse();
        }
    }
    out
}

fn rot13(data: &[u8]) -> Vec<u8> {
    data.iter()
        .map(|&b| match b {
            b'a'..=b'z' => (b - b'a' + 13) % 26 + b'a',
            b'A'..=b'Z' => (b - b'A' + 13) % 26 + b'A',
            _ => b,
        })
        .collect()
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn hex_encode(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() * 2);
    for b in data {
        out.push(b"0123456789abcdef"[(b >> 4) as usize]);
        out.push(b"0123456789abcdef"[(b & 0xf) as usize]);
    }
    out
}

fn hex_decode(data: &[u8]) -> Result<Vec<u8>, String> {
    let f: Vec<u8> = data.iter().copied().filter(|b| !b.is_ascii_whitespace()).collect();
    if !f.len().is_multiple_of(2) {
        return Err("unhex: odd number of hex digits".into());
    }
    f.chunks(2)
        .map(|p| Ok((hexval(p[0])? << 4) | hexval(p[1])?))
        .collect()
}

pub fn b64_encode(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        out.push(B64[(b[0] >> 2) as usize]);
        out.push(B64[(((b[0] & 0x03) << 4) | (b[1] >> 4)) as usize]);
        out.push(if chunk.len() > 1 {
            B64[(((b[1] & 0x0f) << 2) | (b[2] >> 6)) as usize]
        } else {
            b'='
        });
        out.push(if chunk.len() > 2 {
            B64[(b[2] & 0x3f) as usize]
        } else {
            b'='
        });
    }
    out
}

fn b64_decode(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut rev = [255u8; 256];
    for (i, &c) in B64.iter().enumerate() {
        rev[c as usize] = i as u8;
    }
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for &c in data {
        if c == b'=' || c.is_ascii_whitespace() {
            continue;
        }
        let v = rev[c as usize];
        if v == 255 {
            return Err(format!("unbase64: invalid character '{}'", c as char));
        }
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Ok(out)
}

fn url_encode(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    for &b in data {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b);
        } else {
            out.extend_from_slice(format!("%{b:02X}").as_bytes());
        }
    }
    out
}

fn url_decode(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        if data[i] == b'%' {
            if i + 2 >= data.len() {
                return Err("unurl: truncated % escape".into());
            }
            out.push((hexval(data[i + 1])? << 4) | hexval(data[i + 2])?);
            i += 3;
        } else {
            out.push(data[i]);
            i += 1;
        }
    }
    Ok(out)
}

/// Stream `data` through `sh -c <cmdline>` (stdin → stdout). Lets a transform
/// be written in any language. A writer thread avoids stdin/stdout deadlock.
fn pipe(data: &[u8], cmdline: &str) -> Result<Vec<u8>, String> {
    use std::io::{Read, Write};
    use std::process::{Command, Stdio};

    if cmdline.trim().is_empty() {
        return Err("pipe: need a command, e.g. `pipe zcat`".into());
    }
    let mut child = Command::new("sh")
        .arg("-c")
        .arg(cmdline)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("pipe: {e}"))?;

    let mut stdin = child.stdin.take().unwrap();
    let owned = data.to_vec();
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&owned);
        // stdin dropped here → EOF for the child
    });

    let mut out = Vec::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_end(&mut out)
        .map_err(|e| format!("pipe: read stdout: {e}"))?;
    let mut errout = String::new();
    if let Some(mut se) = child.stderr.take() {
        let _ = se.read_to_string(&mut errout);
    }
    let _ = writer.join();
    let status = child.wait().map_err(|e| format!("pipe: {e}"))?;
    if !status.success() {
        let msg = errout.trim();
        return Err(format!(
            "pipe: `{cmdline}` failed ({status}){}",
            if msg.is_empty() {
                String::new()
            } else {
                format!(": {msg}")
            }
        ));
    }
    Ok(out)
}

// --- named pipelines (~/.bxpipes) --------------------------------------------

fn pipes_path() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".bxpipes"))
}

/// Load `~/.bxpipes`: `name = op | op | …` lines, `#` comments. Returns the
/// named recipes plus any warnings about lines that couldn't be parsed.
pub fn load_pipelines() -> (HashMap<String, Vec<String>>, Vec<String>) {
    let mut pipes = HashMap::new();
    let mut warnings = Vec::new();
    let Some(path) = pipes_path() else {
        return (pipes, warnings);
    };
    let Ok(text) = std::fs::read_to_string(&path) else {
        return (pipes, warnings);
    };
    for (lineno, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((name, recipe)) = line.split_once('=') else {
            warnings.push(format!(".bxpipes:{}: expected name = op | op", lineno + 1));
            continue;
        };
        let ops: Vec<String> = recipe
            .split('|')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if ops.is_empty() {
            warnings.push(format!(".bxpipes:{}: empty recipe", lineno + 1));
            continue;
        }
        pipes.insert(name.trim().to_string(), ops);
    }
    (pipes, warnings)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(recipe: &[&str], input: &[u8]) -> Result<Vec<u8>, String> {
        run(&recipe.iter().map(|s| s.to_string()).collect::<Vec<_>>(), input)
    }

    #[test]
    fn base64_roundtrip() {
        assert_eq!(b64_encode(b"hello"), b"aGVsbG8=");
        assert_eq!(b64_decode(b"aGVsbG8=").unwrap(), b"hello");
        assert_eq!(r(&["base64", "unbase64"], b"\x00\x01\x02\xff").unwrap(), b"\x00\x01\x02\xff");
    }

    #[test]
    fn hex_and_xor() {
        assert_eq!(r(&["hex"], b"AB").unwrap(), b"4142");
        assert_eq!(r(&["unhex"], b"4142").unwrap(), b"AB");
        // xor with repeating 2-byte key is its own inverse
        let enc = r(&["xor dead"], b"secret bytes").unwrap();
        assert_eq!(r(&["xor dead"], &enc).unwrap(), b"secret bytes");
    }

    #[test]
    fn rot13_and_case() {
        assert_eq!(r(&["rot13"], b"Hello, Zeb!").unwrap(), b"Uryyb, Mro!");
        assert_eq!(r(&["upper"], b"abcXYZ").unwrap(), b"ABCXYZ");
    }

    #[test]
    fn swap_and_slice() {
        assert_eq!(r(&["swap32"], &[1, 2, 3, 4]).unwrap(), vec![4, 3, 2, 1]);
        assert_eq!(r(&["drop 2", "take 1"], &[9, 8, 7, 6]).unwrap(), vec![7]);
    }

    #[test]
    fn chained_recipe_and_errors() {
        // base64-of-rot13 then undo
        let out = r(&["rot13", "base64"], b"data").unwrap();
        let back = r(&["unbase64", "rot13"], &out).unwrap();
        assert_eq!(back, b"data");
        assert!(r(&["bogus"], b"x").unwrap_err().contains("unknown op"));
        assert!(r(&["unhex"], b"abc").unwrap_err().contains("odd"));
    }

    #[test]
    fn pipe_through_external_program() {
        // `cat` is a harmless identity filter present on any unix
        assert_eq!(r(&["pipe cat"], b"roundtrip").unwrap(), b"roundtrip");
        assert_eq!(r(&["pipe tr a-z A-Z"], b"hello").unwrap(), b"HELLO");
    }
}
