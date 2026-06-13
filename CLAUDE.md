Build a terminal binary analysis tool in Rust called "bx".

UI & Layout:
- ratatui + crossterm TUI with a configurable pane layout:
  - Hex view (offset | hex bytes | ASCII sidebar)
  - Structure/annotation pane (user-defined regions with labels and types)
  - Info/output bar at the bottom
- Vim-style keybindings throughout

Dependencies (cargo only, no system packages):
- ratatui + crossterm for TUI
- memmap2 for zero-copy file mapping (important for large firmware blobs)
- md5 crate for file hashing
- serde + serde_json for .bxa annotation files and JSON export

Navigation & Editing:
- Seek to offset with :seek <hex> or g<hex>g
- Hex and ASCII editing modes (toggle with Tab)
- Undo/redo stack for edits
- Visual selection mode (v) with byte range highlighting

Search & Analysis:
- Byte pattern search: /xx xx xx ?? xx (with wildcard support)
- String search (ASCII + UTF-16LE)
- Entropy visualization per region (rendered as a bar graph in-pane)
- XOR brute-force against a selected region (tries keys 0x00-0xFF, shows printable hits)
- Cyclic pattern detection (for recognizing repeating structures)

Diffing:
- Load two files and diff them side by side (:diff <file>)
- Highlight added/removed/changed byte regions with color
- Jump between diff hunks with n/N

Annotations:
- Define named regions: :mark <start> <end> <label> <type>
  - Types: u8, u16le, u16be, u32le, u32be, u64le, u64be, float, str, raw
- Annotations saved to a sidecar file (<binary>.bxa) in a simple text format
- Annotations panel shows parsed value of each marked region live
- Color-coded highlighting of annotated regions in hex view

Structs:
- Define simple structs in a .bxs file (C-struct-like syntax)
- Apply a struct at cursor offset: :applystruct <structname>
- Auto-annotates all fields with parsed values

Architecture Pattern Awareness (heuristic pattern match only, no disassembly):
- Detect and highlight common function prologue/epilogue byte patterns for:
  - x86/x86_64: 55 48 89 E5 (push rbp / mov rbp rsp), C3 (ret), 90 (nop sled)
  - ARM32: PUSH {R4, LR} variants, BX LR epilogues
  - ARM64: STP X29, X30 prologues, RET epilogues
  - MIPS: addiu sp / sw ra patterns
  - PowerPC: mflr r0 / stw r0 prologues
  - RISC-V: addi sp,sp / sd ra patterns
- Flag NOP sleds, int3 sequences, and zero-filled padding regions
- All matches clearly labeled as heuristic in the UI

Magic Byte Detection (scan entire file on load, list all hits with offsets in info pane):
  Executables & objects:
  - ELF (all classes/endians), PE/MZ, Mach-O (32/64/fat), COFF, .a static lib,
    DEX (dex\n035/036/037/038/039), VDEX, OAT, ART, OdexV035

  Firmware & bootloaders:
  - Android boot image v0-v3 (ANDROID!), vendor boot (VNDRBOOT),
    U-Boot uImage/FIT, SquashFS (all endian variants), JFFS2, UBIFS,
    YAFFS2, cramfs, romfs, ext2/3/4, F2FS

  Archives & compression:
  - gzip, zlib (all preset bytes), LZMA, LZ4, Zstandard, bzip2,
    XZ, 7zip, ZIP, RAR, tar

  Certificates & crypto:
  - DER/PEM x509, PKCS#8, PKCS#12, OpenSSH private key,
    Android OTA payload.bin header

  Media & misc:
  - PNG, JPEG, BMP, SQLite3, protobuf (heuristic), msgpack (heuristic)

  On load: parse and display format-specific headers where magic matches:
  - ELF: e_machine, e_entry, e_phoff, section count
  - Android boot image: parse header v0-v3 fields fully
  - PE/MZ: machine type, entrypoint, section table summary
  - DEX: version, class count, checksum

Misc:
- File info on load: size, entropy, detected filetype, MD5
- Jump to offset by hex, decimal, or annotation label
- Export annotated regions to JSON report
- Config file (~/.bxrc) for colors, column width, default pane layout
- cargo install support, include a README with usage

---

# Project ethos (keep in mind for all future work)

- **Fast and lightweight**, but aiming to be better than 010 Editor and as
  close to a de-facto terminal RE tool as possible.
- **Pure-cargo, no system packages.** Hand-roll where reasonable (CRC/SHA,
  parsers, pattern matchers). If a heavy dependency is ever needed
  (disassembly, decompression), it must be **pure-Rust** and behind a cargo
  **feature flag** so a minimal build stays tiny.
- **The hex-view hot path stays untouched.** All analysis is on-demand or in a
  separate pane; whole-file passes are lazy + cached + windowed. mmap means
  multi-GB files open instantly.
- Workflow: build a feature, then verify it live in a PTY (pyte-based harness
  in /tmp/bxvenv) before calling it done. Keep `cargo clippy --all-targets`
  clean and all unit tests passing.

# Milestones COMPLETED beyond the original spec

Milestone A — 010-parity features:
- **Checksum calculator** (`#` / `:checksum [start end]`): Sum8/16/32, XOR8,
  Adler-32, CRC32, MD5, SHA-1, SHA-256 over selection or whole file. All
  hand-rolled in `analysis/checksum.rs` (MD5 via existing crate); validated
  against canonical test vectors.
- **Data inspector** (Inspect side tab): live decode of bytes at cursor as
  every int width (signed/unsigned × LE/BE × 8/16/32/64), f32/f64, time_t,
  hex/oct/bin/ASCII. `inspector.rs`.
- **Multiple files** (tabs): `App` owns `Vec<Document>` and derefs to the
  active one (per-file: buf, annotations, search, analysis, cursor, etc.).
  `bx a b c` opens tabs; `gt`/`gT`, `:e`, `:bn`/`:bp`/`:b<n>`, `:ls`,
  `:close`; `:q` closes active then quits on last; `:qa`. `--diff` flag
  preserves the old side-by-side diff. Tab strip across the top.

Milestone B — navigation & xrefs:
- **Jump list**: `Ctrl-o`/`Ctrl-p` back/forward through seeks/searches/
  follows/bookmark-jumps/magic hits (browser-history model, per file). `:jumps`.
- **Bookmarks**: `m<key>` set, `` `<key> `` jump, `:bookmarks` list. **Persisted
  to the `.bxa` sidecar** (`bookmarks` map, serde default for back-compat).
- **Follow pointer**: `f`/`F` read 32/64-bit value at cursor and jump
  (offset = value − `:base`); `:endian le|be`; width/endian auto-detected from
  an ELF header. `:follow [u32le|…]`.
- **Cross-references**: `X` / `:xref` scans the file for pointers equal to the
  cursor offset, loaded as search hits so `n`/`N` cycle them.
- **Strings pane** (Strings side tab, `analysis/strings.rs`): ASCII + optional
  UTF-16LE, cached + windowed for speed. Live filter with `\` (or `:sfind`),
  `Enter` jumps to first match.
- **Side-tab strip wraps** to multiple rows when too narrow (manual layout;
  ratatui `Tabs` is single-line).

# Roadmap (next thrusts, in recommended order)

1. **Template/struct language v2** — the core "beat 010/ImHex" lever. Nested
   structs, arrays sized by earlier fields, enums, bitfields, conditionals,
   pointers. Pure logic, no heavy deps. (Current `.bxs` is flat only.)
2. **Disassembly pane** — read-only instruction view at the cursor via
   pure-Rust `yaxpeax-*`. The leap from "hex editor" to "RE tool". One curated,
   feature-gated dependency. (Spec said heuristic-only; revisit deliberately.)
3. **Firmware extraction / transforms** — decompress detected gzip/zlib/lzma/
   zstd regions into a new tab; CyberChef-lite transform pipeline
   (XOR/rotate/base64). Optional deps behind a cargo feature.
4. **Search performance** — replace the naive O(n·m) scan with a memchr-style
   skip / Boyer-Moore for snappy large-file search.
