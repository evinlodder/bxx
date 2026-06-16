//! Security / robustness fuzz sweep: feed random and adversarial inputs through
//! every parser and analyzer and assert nothing panics, overflows (debug
//! builds panic on overflow, so this catches those too), hangs, or OOMs.
//!
//! This module is compiled only for tests.

use crate::analysis::{arch, checksum, cyclic, entropy, headers, magic, strings, triage, xor};
use crate::buffer::FileBuffer;
use crate::{diff, inspector, search, structs, transform};

/// Small deterministic PRNG (xorshift) so the sweep is reproducible.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn byte(&mut self) -> u8 {
        (self.next() & 0xff) as u8
    }
}

/// A diverse set of adversarial byte blobs.
fn blobs() -> Vec<Vec<u8>> {
    let mut rng = Rng(0x9e3779b97f4a7c15);
    let mut out: Vec<Vec<u8>> = vec![
        vec![],
        vec![0],
        vec![0xff],
        b"\x7fELF".to_vec(),                              // truncated ELF magic
        b"\x7fELF\x02\x01\x01".to_vec(),                  // ELF64 header cut short
        b"\x7fELF\x01\x02\x01".to_vec(),                  // ELF32 big-endian, cut
        b"MZ".to_vec(),                                   // truncated PE
        b"\x89PNG\r\n\x1a\n".to_vec(),                    // PNG sig only
        b"\x1f\x8b\x08".to_vec(),                         // gzip header cut
        b"PK\x03\x04".to_vec(),                           // zip local header cut
        b"ANDROID!".to_vec(),                             // boot image magic only
        vec![0u8; 4096],
        vec![0xffu8; 4096],
    ];
    // random blobs of varied sizes
    for &len in &[1usize, 3, 7, 13, 16, 17, 63, 64, 65, 200, 257, 1000, 4096] {
        out.push((0..len).map(|_| rng.byte()).collect());
    }
    // random blobs prefixed with a real magic, then garbage (header parsers near EOF)
    for magic in [
        &b"\x7fELF\x02\x01\x01\x00"[..],
        &b"\x7fELF\x01\x01\x01\x00"[..],
        b"MZ",
        b"\x89PNG\r\n\x1a\n",
        b"dex\n035\0",
        b"ANDROID!",
    ] {
        for &len in &[0usize, 4, 40, 200] {
            let mut v = magic.to_vec();
            v.extend((0..len).map(|_| rng.byte()));
            out.push(v.clone());
            // and the same magic placed at the very end of a buffer
            let mut w: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
            w.extend_from_slice(magic);
            out.push(w);
        }
    }
    out
}

fn fixture(bytes: &[u8], tag: usize) -> FileBuffer {
    let p = std::env::temp_dir().join(format!("bxx-fuzz-{tag}-{}", std::process::id()));
    std::fs::write(&p, bytes).unwrap();
    FileBuffer::open(&p).unwrap()
}

#[test]
fn fuzz_analyzers_never_panic() {
    for (i, b) in blobs().iter().enumerate() {
        // whole-file analyzers over raw bytes
        let (mhits, _) = magic::scan(b);
        let _ = magic::detect_type(&mhits);
        let _ = arch::scan(b);
        let _ = entropy::shannon(b);
        for buckets in [0usize, 1, 3, 7, 64, 1000] {
            let _ = entropy::bucketed(b, buckets);
        }
        for min in [0usize, 1, 4, 100] {
            let _ = strings::extract(b, min, false);
            let _ = strings::extract(b, min, true);
        }
        let _ = checksum::all(b);
        let _ = checksum::crc32(b);
        let _ = checksum::adler32(b);
        let _ = checksum::sha1(b);
        let _ = checksum::sha256(b);
        let _ = xor::brute_force(b, 0.0);
        let _ = cyclic::detect(b, 64, 0.5);
        let _ = triage::analyze(b);
        // header parsers at every magic hit (exercises near-EOF reads)
        for h in &mhits {
            let _ = headers::parse_for(h.name, b, h.offset as usize);
            // also at deliberately out-of-range offsets
            let _ = headers::parse_for(h.name, b, b.len());
            let _ = headers::parse_for(h.name, b, b.len().wrapping_add(1000));
        }

        // FileBuffer-based: search / inspector / diff
        let buf = fixture(b, i);
        for q in [
            "00", "ff ?? 00", "\"data\"", "i\"DATA\"", "?? ??", "de ad be ef", "re:[0-9]+",
        ] {
            let _ = search::run_search(&buf, q);
        }
        let _ = search::find_bytes(&buf, &[0x7f, 0x45, 0x4c, 0x46]);
        for &c in &[0u64, 1, 7, b.len() as u64, (b.len() as u64).wrapping_add(99)] {
            let _ = inspector::lines(&buf, c);
        }
        let _ = diff::diff(b, &[]);
        let _ = diff::diff(&[], b);
        if i > 0 {
            let other = &blobs()[i - 1];
            let _ = diff::diff(b, other);
            let _ = diff::compute(b, other, 4);
        }
    }
}

#[test]
fn fuzz_template_apply_is_bounded() {
    // Adversarial templates: huge counts, recursion, expression overflow.
    let templates = [
        "struct S { u8 n; u8 data[n]; }",
        "struct S { u32le n; raw blob[n]; }",
        "struct S { u32le n; str s[n]; }",
        "struct S { S child; }",                      // self-recursion (consumes nothing)
        "struct S { u8 n; S items[n]; }",             // recursion that consumes a byte
        "struct A { B b; } struct B { A a; }",        // mutual recursion
        "struct S { u8 x[100000]; }",                 // many fields -> region cap
        "struct S { raw r[18446744073709551615]; }",  // u64::MAX length
        "struct S { u8 n; str s[n * n * n * 99999]; }", // expression overflow
        "struct S { u8 a; if (a == 0) { u32le b; } else { u8 c; } }",
        "struct S { u8 a; if (missing == 1) { u8 b; } }", // unknown ident in expr
    ];
    let data: Vec<u8> = (0..512u32).map(|x| (x * 7) as u8).collect();
    let buf = fixture(&data, 9001);
    for src in templates {
        if let Ok(tpl) = structs::parse(src) {
            for base in [0u64, 1, 256, 511, 512, u64::MAX - 4, u64::MAX] {
                let (regions, _warn) = tpl.apply("S", base, &buf);
                assert!(regions.len() <= 8192, "region cap exceeded for {src}");
                let _ = tpl.apply("A", base, &buf);
            }
        }
    }
}

#[test]
fn fuzz_parser_never_panics() {
    let mut rng = Rng(0xdead_beef_cafe_babe);
    // tokens likely to stress the lexer/parser
    let toks = [
        "struct", "enum", "bitfield", "if", "else", "{", "}", "[", "]", "(", ")", ";", ":", ",",
        "=", "u8", "u32le", "str", "raw", "0x", "==", "<<", "&&", "||", "Foo", "999999999999",
        "\n", " ",
    ];
    for _ in 0..2000 {
        let n = (rng.next() % 40) as usize;
        let mut s = String::new();
        for _ in 0..n {
            s.push_str(toks[(rng.next() as usize) % toks.len()]);
            s.push(' ');
        }
        let _ = structs::parse(&s); // must return Ok or Err, never panic
    }
    // also feed raw random bytes interpreted as text
    for _ in 0..500 {
        let len = (rng.next() % 200) as usize;
        let bytes: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
        let s = String::from_utf8_lossy(&bytes);
        let _ = structs::parse(&s);
    }
}

#[test]
fn fuzz_transform_ops_never_panic() {
    let mut rng = Rng(0x0123_4567_89ab_cdef);
    let ops = [
        "hex", "unhex", "base64", "unbase64", "url", "unurl", "xor 5a", "xor",
        "xor deadbeef", "add 200", "sub 1", "not", "rol 3", "ror 9", "reverse", "swap16",
        "swap32", "swap64", "rot13", "upper", "lower", "take 0", "take 99999", "drop 3",
        "md5", "sha1", "sha256", "crc32", "bogusop",
    ];
    for _ in 0..400 {
        let len = (rng.next() % 300) as usize;
        let data: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
        for op in ops {
            let _ = transform::apply_op(op, &data); // Ok or Err, never panic
        }
    }
}
