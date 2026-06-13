# bx

A terminal binary analysis tool for reverse engineers: vim-style hex
viewer/editor with annotations, struct templates, diffing, entropy
visualization, XOR brute-forcing, magic-byte scanning, and heuristic
architecture detection. Built for firmware blobs — files are memory-mapped,
so multi-hundred-MB images open instantly and navigation stays smooth.

> [!NOTE]
> **Disclaimer:** this is primarily a curiosity / hobby project, and a large
> portion of the code is AI-generated. It's reasonably tested but has not been
> battle-hardened — treat it accordingly, and don't rely on it for anything
> safety- or security-critical without reviewing the code yourself.

```
┌ fw.bin ────────────────────────────────────────────────┐┌───────────────────────────┐
│00000000  41 4E 44 52 4F 49 44 21  00 00 80 00  ANDROID!││ Marks │ Analysis │ … │    │
│00000010  00 00 20 00 00 00 00 00  00 00 00 00  ·· ·····││ bhdr.kernel_size u32le    │
│…                                                       ││   = 8388608 (0x800000)    │
└────────────────────────────────────────────────────────┘└───────────────────────────┘
 NORMAL  0x0/0x1A9F  Android boot image | H=3.62 | md5 748bb902c38d
```

## Install

```sh
cargo install --path .
# or just
cargo build --release   # binary at target/release/bx
```

Pure-cargo dependencies only (ratatui, crossterm, memmap2, md5, serde).

## Usage

```sh
bx file.bin              # open in the TUI
bx a.bin b.bin c.bin     # open several files as tabs (gt/gT to switch)
bx --diff a.bin b.bin    # open with a side-by-side diff
bx file.bin --batch      # headless: print file info, magic hits, parsed
                         # headers and arch summary to stdout, then exit
```

On load, bx computes the file's size, MD5, Shannon entropy and detected type,
scans the **entire file** for magic signatures (embedded images included), and
runs the heuristic architecture pattern scan. Results land in the **Analysis**
tab of the side pane.

## Keys (vim-style)

| Key | Action |
|---|---|
| `h j k l` / arrows | move by byte / row |
| `w` / `b` | row forward / back |
| `0` / `$` | start / end of row |
| `Ctrl-d` / `Ctrl-u` | half page down / up |
| `Ctrl-f` / `Ctrl-b`, PgDn / PgUp | full page |
| `gg` / `G` | start / end of file |
| `g<hex>g` | seek to hex offset (e.g. `g1845g`) |
| `Ctrl-o` / `Ctrl-p` | jump list — back / forward through visited positions |
| `m<key>` / `` `<key> `` | set bookmark / jump to bookmark (`a-z`, `0-9`) |
| `f` / `F` | follow the 32-/64-bit pointer under the cursor (honours base+endian) |
| `X` | find xrefs — every pointer in the file that targets the cursor (cycle with `n`/`N`) |
| `/` | search — hex with wildcards (`de ad ?? ef`) or string (`"text"`, matches ASCII **and** UTF-16LE) |
| `n` / `N` | next / prev search hit (or diff hunk while a diff is open) |
| `\` | live-filter the Strings tab (type to narrow; `Enter` jumps to first match) |
| `{` / `}` | prev / next magic-byte hit |
| `<` / `>` | smaller / larger side-pane |
| `v` | visual selection (movement extends; `Esc`/`v` ends) |
| `m` (in visual) | pre-fill `:mark` for the selection |
| `x` | XOR brute-force the selection (keys 0x00–0xFF, printable hits ranked) |
| `c` | cyclic / repeating-structure detection on the selection |
| `#` | checksums (CRC32/MD5/SHA1/SHA256/…) of the selection, or whole file |
| `gt` / `gT` | switch to next / previous open file |
| `i` | edit mode — type hex nibbles; `Tab` switches to ASCII overtype; `Esc` ends |
| `u` / `Ctrl-r` | undo / redo (grouped per edit session) |
| `e` | toggle entropy graph |
| `Tab` | cycle side-pane tab (Marks → Inspect → Strings → Analysis → Entropy → Output) |
| `J` / `K` | scroll side pane |
| `q` | quit / close active file (refuses if unsaved; `:q!` discards) |

## Commands

```
:seek <target>            jump to 0x<hex>, bare hex, 0d<decimal>, or a mark label
:mark <start> <end> <label> <type>   annotate [start,end) — types: u8 u16le u16be
                                     u32le u32be u64le u64be float str raw
:unmark <label>
:applystruct <name>       lay a struct template down at the cursor
:loadstructs <file.bxs>   load extra struct definitions
:diff <file> / :diffoff   side-by-side diff; changed/added/removed colored
:xor / :cyclic            analyze the last visual selection
:checksum [start end]     CRC32/Adler/MD5/SHA1/SHA256 of a range (default: selection/file)
:strings [min] [utf16]    list printable strings in the Strings tab
:follow [u32le|u64be|…]   follow the pointer under the cursor (also f / F)
:xref [u32le|u64be|…]     find pointers that target the cursor (also X)
:base <hex>               load base subtracted by follow/xref (firmware @ nonzero base)
:endian le|be             byte order used by follow/xref (auto-set from ELF)
:bookmarks  :jumps        list bookmarks / jump-list state
:e <file>                 open another file in a new tab
:bn :bp :b <n> :ls        next / prev / nth file; list open files
:close  :bd[!]            close the active file
:export <report.json>     JSON report: file info + annotations with parsed values
:w [file]                 write patches in place, or a patched copy to [file]
:revert                   discard unsaved edits in the active file
:q  :q!  :wq  :qa[!]      quit-or-close / discard / write+quit / quit all
:info :inspect :entropy :help    switch side-pane tabs
```

## Annotations (`.bxa`)

Marks (and bookmarks) are saved automatically to a JSON sidecar `<binary>.bxa`
and reloaded next session (with an MD5 mismatch warning if the file changed).
The Marks tab shows each region's **live** decoded value — it re-decodes
through your unsaved edits. Annotated bytes are color-coded in the hex view,
and labels work as `:seek` targets.

## Struct templates (`.bxs`)

C-like definitions, auto-loaded from `<binary>.bxs`:

```c
struct boot_hdr {
    str magic[8];
    u32le kernel_size;
    u32le kernel_addr;
    raw reserved[16];     // fixed-size types take no [len]
    u16le flags[4];       // arrays of scalars are sized automatically
}
```

`:applystruct boot_hdr` at the cursor annotates every field
(`boot_hdr.kernel_size`, …) with parsed values.

## Analysis

- **Magic scan** — executables (ELF, PE/MZ, Mach-O incl. fat, COFF, ar, DEX
  035–039, ODEX, VDEX, OAT, ART), firmware (Android boot/vendor_boot, uImage,
  FIT/DTB, SquashFS ×4, JFFS2, UBI/UBIFS, YAFFS2, cramfs, romfs, ext2/3/4,
  F2FS), archives (gzip, zlib ×4, LZMA, LZ4, zstd, bzip2, XZ, 7z, ZIP, RAR,
  tar), crypto (DER x509 / PKCS#8 / PKCS#12, PEM banners, OpenSSH keys,
  Android OTA payload), media (PNG, JPEG, BMP, SQLite3, protobuf/msgpack
  heuristics). Short magics carry validators (e.g. MZ → e_lfanew → `PE\0\0`,
  tar checksum field, ext superblock sanity) to keep firmware noise down;
  noisy entries are capped per type and flagged as truncated.
- **Header parsing** — ELF (class/endian, machine, entry, phoff, section
  count), PE (machine, entrypoint RVA, section table), Android boot image
  v0–v4 (full field set per version), DEX (version, checksum, class count) —
  parsed wherever the magic lands, so embedded images decode too.
- **Arch patterns** *(heuristic, no disassembly — labeled as such)* —
  prologue/epilogue signatures for x86/x86_64, ARM32 (ARM+Thumb), ARM64,
  MIPS (LE/BE), PowerPC, RISC-V, plus NOP sleds, `int3` runs and zero-fill
  padding. Matches are tinted in the hex view (padding dimmed).
- **Entropy** — whole-file value in the status bar; per-region bar graph in
  the Entropy tab (red ≈ compressed/encrypted), cursor position highlighted.
- **XOR brute force** — select a region, press `x`; all 256 keys tried,
  candidates ranked by printability/text-likeness with decoded previews.
- **Cyclic detection** — select a region, press `c`; reports repeating record
  periods (2–64 bytes) by self-similarity.
- **Checksums** — press `#` (or `:checksum`) to compute Sum8/16/32, XOR8,
  Adler-32, CRC32, MD5, SHA-1 and SHA-256 over the selection (or the whole
  file if nothing is selected). CRC/Adler/SHA are hand-rolled — no extra deps.
- **Data inspector** — the **Inspect** tab decodes the bytes at the cursor as
  every integer width (signed/unsigned, LE/BE), `float32`/`float64`, a 32-bit
  `time_t`, plus hex/octal/binary/ASCII — live, no `:mark` needed.

## Multiple files

Open several files at once (`bx a b c`, or `:e <file>` while running); each is
a tab in the strip across the top with its own cursor, annotations, search and
analysis. `gt`/`gT` (or `:bn`/`:bp`/`:b <n>`) switch between them, `:ls` lists
them, `:close` closes one. `:q` closes the active file and only quits once the
last one is gone (`:qa` quits everything). `:diff` is still the way to compare
two files byte-for-byte side by side.

## Navigation & xrefs

The moment-to-moment RE loop — jump somewhere, look, come back:

- **Jump list** — every seek, search, follow, bookmark-jump and magic hit is
  recorded; `Ctrl-o` walks back through where you've been and `Ctrl-p` forward
  (browser-style history, per file). `:jumps` shows the stack.
- **Bookmarks** — `m<key>` drops a named position (`a-z`/`0-9`), `` `<key> ``
  jumps to it, `:bookmarks` lists them.
- **Follow pointer** — `f`/`F` read the 32-/64-bit value under the cursor and
  jump there. For images loaded at a non-zero address, set `:base <hex>` and
  the file offset is computed as `value − base`; `:endian le|be` picks byte
  order (auto-detected from an ELF header). `:follow u64be` overrides per-call.
- **Cross-references** — `X` (or `:xref`) scans the whole file for pointers
  whose value equals the cursor offset (`+ base`), loading them as search hits
  so `n`/`N` cycle them and they highlight in the hex view. Pointer width and
  endianness default to the detected ELF class.
- **Strings** — the **Strings** tab lists printable ASCII (and, with
  `:strings <min> utf16`, UTF-16LE) runs with offsets; the entry nearest the
  cursor is highlighted, and the list is windowed so even huge files stay
  snappy. Press `\` (or `:sfind <text>`) to live-filter the list by substring;
  `Enter` jumps the cursor to the first match.

Bookmarks persist to the `.bxa` sidecar, so they survive across sessions.

## Editing model

Overwrite-only by design: insertion would shift offsets and silently
invalidate annotations and diffs, which is the wrong default for binary
patching. Edits live in an overlay (the mapped file is untouched) until `:w`
patches the file in place or `:w copy.bin` writes a patched copy. Modified
bytes are highlighted; undo/redo is unlimited. Diff mode compares on-disk
contents.

## Config (`~/.bxrc`)

`key = value` lines, `#` comments:

```ini
columns = 16            # bytes per hex row (1-64)
anno_pane = right       # right | left | off
anno_width = 44
color.annotation = cyan        # named colors or #rrggbb
color.cursor = yellow
color.selection = blue
color.search = green
color.diff_changed = yellow
color.diff_added = green
color.diff_removed = red
color.heuristic = magenta
color.modified = lightred
```
