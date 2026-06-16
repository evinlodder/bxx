//! Built-in `.bxs` templates for common formats, merged into every document so
//! `:applystruct elf64_header` (etc.) work with no sidecar file. User templates
//! from `<file>.bxs` are merged afterward and override these by name.

pub const BUILTINS: &str = r#"
// ---- ELF ----------------------------------------------------------------
enum elf_type : u16le { NONE = 0, REL = 1, EXEC = 2, DYN = 3, CORE = 4 }
enum elf_machine : u16le {
    X86 = 3, MIPS = 8, PPC = 20, ARM = 40, X86_64 = 62, AARCH64 = 183, RISCV = 243,
}

struct elf64_header {
    str   magic[4];
    u8    ei_class;
    u8    ei_data;
    u8    ei_version;
    u8    ei_osabi;
    raw   ei_pad[8];
    elf_type     e_type;
    elf_machine  e_machine;
    u32le e_version;
    u64le e_entry;
    u64le e_phoff;
    u64le e_shoff;
    u32le e_flags;
    u16le e_ehsize;
    u16le e_phentsize;
    u16le e_phnum;
    u16le e_shentsize;
    u16le e_shnum;
    u16le e_shstrndx;
}

struct elf32_header {
    str   magic[4];
    u8    ei_class;
    u8    ei_data;
    u8    ei_version;
    u8    ei_osabi;
    raw   ei_pad[8];
    elf_type     e_type;
    elf_machine  e_machine;
    u32le e_version;
    u32le e_entry;
    u32le e_phoff;
    u32le e_shoff;
    u32le e_flags;
    u16le e_ehsize;
    u16le e_phentsize;
    u16le e_phnum;
    u16le e_shentsize;
    u16le e_shnum;
    u16le e_shstrndx;
}

enum elf_ptype : u32le { NULL = 0, LOAD = 1, DYNAMIC = 2, INTERP = 3, NOTE = 4, PHDR = 6, TLS = 7 }
bitfield elf_pflags : u32le { exec : 1, write : 1, read : 1, pad : 29 }

// Apply at a program-header offset (e_phoff + i * e_phentsize).
struct elf64_phdr {
    elf_ptype  p_type;
    elf_pflags p_flags;
    u64le      p_offset;
    u64le      p_vaddr;
    u64le      p_paddr;
    u64le      p_filesz;
    u64le      p_memsz;
    u64le      p_align;
}

// ---- PNG (signature + the leading IHDR chunk) --------------------------
enum png_color : u8 { GRAY = 0, RGB = 2, PALETTE = 3, GRAY_ALPHA = 4, RGBA = 6 }

struct png {
    raw       sig[8];
    u32be     ihdr_len;
    str       ihdr_type[4];
    u32be     width;
    u32be     height;
    u8        bit_depth;
    png_color color_type;
    u8        compression;
    u8        filter;
    u8        interlace;
    u32be     ihdr_crc;
}

// ---- GIF (header + logical screen descriptor) --------------------------
struct gif {
    str   signature[3];
    str   version[3];
    u16le width;
    u16le height;
    u8    flags;
    u8    bg_color;
    u8    aspect_ratio;
}

// ---- BMP (file header + start of DIB header) ---------------------------
struct bmp {
    str   magic[2];
    u32le size;
    u16le reserved1;
    u16le reserved2;
    u32le pixel_offset;
    u32le dib_size;
    u32le dib_width;
    u32le dib_height;
    u16le planes;
    u16le bpp;
    u32le compression;
    u32le image_size;
}

// ---- ZIP local file header (length-prefixed name) ----------------------
struct zip_local {
    str   signature[4];
    u16le version;
    u16le flags;
    u16le method;
    u16le mod_time;
    u16le mod_date;
    u32le crc32;
    u32le comp_size;
    u32le uncomp_size;
    u16le name_len;
    u16le extra_len;
    str   name[name_len];
}

// ---- gzip member header ------------------------------------------------
struct gzip {
    raw   magic[2];
    u8    method;
    u8    flags;
    u32le mtime;
    u8    extra_flags;
    u8    os;
}
"#;

#[cfg(test)]
mod tests {
    use crate::structs;

    #[test]
    fn builtins_parse() {
        let tpl = structs::parse(super::BUILTINS).expect("built-in templates parse");
        for name in ["elf64_header", "elf32_header", "elf64_phdr", "png", "gif", "bmp", "zip_local"]
        {
            assert!(tpl.has_struct(name), "missing built-in: {name}");
        }
    }
}
