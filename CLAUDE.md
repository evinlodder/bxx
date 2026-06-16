Build a terminal binary analysis tool in Rust called "bxx".

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
  `bxx a b c` opens tabs; `gt`/`gT`, `:e`, `:bn`/`:bp`/`:b<n>`, `:ls`,
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

Milestone C — template/struct language v2 (`structs.rs`, the `Template` engine):
- Replaced the flat `.bxs` parser with a small C-like language (lexer + Pratt
  expression parser + buffer-aware apply). Backward compatible with flat structs.
- **Nested structs**, **dynamic arrays** sized by earlier fields with full
  expressions, **enums** (`enum K : u8 { A=1 }` → field shows variant name),
  **bitfields** (`bitfield F : u8 { a:1, b:7 }` → LSB-first group breakdown),
  **`if/else` conditionals**. Operators: + - * / % == != < <= > >= && || & | ^ ~ << >>.
- `Region` gained an optional `note` field (enum/bitfield decode hint), shown
  in the Marks tab and JSON export, persisted in `.bxa` (serde default).
- `:applystruct` walks real bytes; emits nested labels (`Hdr.entries[0].name`),
  warns on EOF overrun / cap (MAX_REGIONS=8192, MAX_DEPTH=64) but keeps partial.
- Deliberately NOT included (keep it simple): loops, local vars, typedefs,
  FSeek/scripting, parent-scope access. Arrays cover repetition.

Milestone C polish (Marks UX + side-pane):
- **Marks tab is now a collapsible tree** (`marks.rs` builds it from the dotted/
  indexed labels). Indented by depth; structs/arrays auto-collapse after
  `:applystruct`. Folds: `za` toggle at cursor, `zR` expand all, `zM` collapse
  all. Rendering is windowed for speed.
- **Template side tab** (`:template`/`:defs`) renders the loaded `.bxs`
  definitions via `Template::describe()`.
- **Side-pane header is a carousel**: single row, scrolls to keep the active
  tab centred, clamped (no wrap-around), with `<`/`>` edge indicators.
  `Tab`/`Shift-Tab` cycle. `SideTab::ORDER` is the single source of order.
  (Replaced the multi-row wrapping strip.)
- Workflow extras: `:applystruct <name> [offset|label]` (apply without seeking);
  re-apply clears the struct namespace first (no orphan marks); `:unmark <name>`
  removes a whole applied struct; `:reloadstructs` re-reads the `.bxs` sidecar;
  `.bxs` parse errors carry `line N` (lexer tracks lines). Milestone C complete.

Milestone D — search performance + transform pipeline:
- **Faster search** (`search.rs`): replaced the per-byte scan with wildcard-aware
  **Boyer-Moore-Horspool** (bad-character skip table over the concrete suffix;
  trailing `??` stripped and re-added to match length; degenerate all-wildcard
  handled). Overlay-aware. 256MB wildcard search ≈ 320ms. Randomized test
  cross-checks against a brute-force reference; overlapping matches handled.
- **Transform pipeline** (`transform.rs` + Transform side tab): CyberChef-style
  recipe over a selection. Built-in pure-Rust ops (hex/base64/url, xor/add/sub/
  not/rol/ror, reverse, swap16/32/64, rot13, upper/lower, take/drop, md5/sha1/
  sha256/crc32). Two custom-transform escape hatches: **`pipe <cmd>`** (streams
  bytes through any external program via `sh -c`, writer-thread to avoid
  deadlock) and **named recipes in `~/.bxpipes`** (`name = op | op`). Keys/cmds:
  `T`/`:transform [name]`, `:t <op>`, `:tpop`, `:tclear`, `:tsave <f>`,
  `:tpatch` (overwrite output back into the buffer), `:pipelines`. Output cached
  on edit (never per-frame, since pipe spawns processes); tab shows recipe +
  hex/ascii + "as text" preview. SideTab order now has 8 entries (Transform
  after Strings).

# Decisions / scope notes
- **In-place extraction / decompression is intentionally OUT.** bxx is a
  companion to binwalk (extraction) and ghidra/equivalents (disassembly), not a
  do-everything tool. `pipe zcat`/`pipe unsquashfs` covers ad-hoc decompression
  without bundling codecs. (User decision, milestone D.)
- **Full disassembly pane is OUT.** bxx is a companion to Ghidra/IDA/Binary
  Ninja, not a competitor in the disassembly/decompilation space. (User decision,
  milestone E.) The *only* disasm we might ever add is a tiny optional
  single-instruction decode under the cursor in the Inspector — not a pane, not
  a feature we lead with.
- **Guiding north star:** make the RE *fast in the terminal*, then hand off
  cleanly to Ghidra/binwalk. "Triage here, deep-dive there."

# Roadmap

## Milestone E (DONE) — triage & Ghidra hand-off + file overview
1. **Structural triage pane** — `analysis/triage.rs` + Triage side tab.
   Parses ELF (32/64, LE/BE): segments, sections, symbols (.symtab/.dynsym),
   imports (undefined dynsyms), needed libs (DT_NEEDED). Display order puts
   high-signal info (libs/imports) first, the big symbol list last. `J`/`K`
   move the highlight, `Enter` (`triage_jump`) jumps the hex cursor to the
   entry's file offset. Cached per-doc (`triage`/`triage_sel`), cleared on
   reanalyze. Pure structure — NO disasm. (PE/Mach-O still TODO.)
2. **File overview minimap** — `ui/minimap.rs`, a 2-col strip carved off the
   RIGHT of the hex view (not in diff mode; only when width allows). Whole file
   → column height, tinted by entropy (own `minimap_cache` keyed by row count
   to avoid thrashing the Entropy tab's cache), annotations highlighted, `┃`
   viewport bracket + `▶` cursor marker. Config `minimap = on|off` in `.bxrc`.
3. **Ghidra / radare2 bridge** — `bridge.rs`; `:export-ghidra <f>` (Jython:
   createLabel + setEOLComment) and `:export-r2 <f>` (`f`/`CCu`). Recreates
   marks + bookmarks at the right ADDRESSES: file offset→vaddr via the triage
   `Report::off_to_vaddr` (ELF LOAD segments); offsets outside any LOAD are
   skipped/counted. Verified: offset 0x25D10 → addr 0x26D10 on /bin/ls.
   Labels sanitized to [A-Za-z0-9_]; comments one-lined.
   **STATUS: PROTOTYPE / experimental** (user decision) — works in the common
   case but not deeply tested across binaries/tool versions; flagged as such in
   the README. Don't treat offset→addr translation or script output as
   guaranteed-correct yet; needs hardening before it's load-bearing.

## Milestone F (DONE — 1.0 shipped) — smarter diff + polish + release
COMPLETED: search history (↑/↓), case-insensitive (`i"…"`) + scoped (`v` then
`/`) + feature-gated regex (`re:`) search; yank/paste/fill (`y`/`p`/`:fill`,
OSC52 clipboard); built-in `.bxs` templates (`builtins.rs`: elf64/32, png/gif/
bmp/zip/gzip) merged into every doc; alignment-aware diff (`diff.rs` difflib
matching-blocks → per-side hunks + similarity %, positional fallback >2MiB);
`--version`; robustness sweep (no panics, batch + TUI). Release prep: Cargo.toml
metadata (v1.0.0, MIT OR Apache-2.0, repo/keywords/categories/rust-version 1.87/
exclude), LICENSE-MIT + LICENSE-APACHE, CHANGELOG.md, README front-page;
`cargo publish --dry-run` passes (40 files, CLAUDE.md excluded).
NOTE: crate+binary = `bxx` (file formats kept `.bx*`); `bx` was taken on
crates.io. Repo = github.com/evinlodder/bx. Not yet committed/published — user
to commit + `cargo publish` (needs their crates.io token).

Original plan/decisions for reference:
Decisions: **license = MIT OR Apache-2.0** (dual). **regex = feature-gated**
(pure-Rust `regex` behind a cargo feature, OFF by default; standard build stays
tiny). **clipboard = OSC52** (escape sequence, no dep, works over SSH).

Part 1 — smarter diff:
- Alignment-aware diff (rolling-hash / content-defined anchors) that survives
  inserted/deleted bytes, not just positional. Similarity % in status bar.
  Diff two regions within one file. Keep positional diff as a fast fallback;
  cap the alignment work and degrade gracefully on huge files.

Part 2 — polish bundle:
- Search: history (↑/↓ recall of `/` and `:` queries), search-in-selection/
  range, case-insensitive string search. Regex (`/re:…`) behind the feature.
- Editing: `y` yank selection to clipboard via OSC52 (hex / C-array / raw /
  base64); `:fill <hex>` fill a selection; paste/overwrite yanked bytes.
- Built-in `.bxs` templates embedded for common formats (ELF/PE/PNG/ZIP/GIF) so
  `:applystruct elf64` works with no sidecar.
- (optional/low-pri) session restore.

Part 3 — 1.0 ship checklist:
- Cargo.toml metadata: description, license = "MIT OR Apache-2.0", repository,
  homepage, keywords, categories, readme, rust-version (edition 2024 ⇒ ≥1.85),
  exclude. Add LICENSE-MIT + LICENSE-APACHE. Version → 1.0.0. CHANGELOG.md.
- `--version` flag. Robustness/no-panic sweep on truncated/malformed/empty/huge
  inputs. README finalized as the crates.io front page (cargo install, features,
  the prototype + AI-generated disclaimers, license section).
- `cargo publish --dry-run`. NOTE: crate name `bxx` may be taken on crates.io —
  user to confirm / pick a fallback (bxhex, bxx-hex, …) before publishing.
