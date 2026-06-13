//! User-defined annotated regions, live value decoding, and `.bxa` sidecar I/O.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use crate::buffer::FileBuffer;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RegionType {
    U8,
    U16Le,
    U16Be,
    U32Le,
    U32Be,
    U64Le,
    U64Be,
    Float,
    Str,
    Raw,
}

impl RegionType {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.to_ascii_lowercase().as_str() {
            "u8" => Self::U8,
            "u16le" => Self::U16Le,
            "u16be" => Self::U16Be,
            "u32le" => Self::U32Le,
            "u32be" => Self::U32Be,
            "u64le" => Self::U64Le,
            "u64be" => Self::U64Be,
            "float" => Self::Float,
            "str" => Self::Str,
            "raw" => Self::Raw,
            _ => return None,
        })
    }

    /// Fixed size in bytes, or None for variable-size types (str/raw/float).
    /// Float accepts 4 (f32) or 8 (f64) byte regions.
    pub fn fixed_size(self) -> Option<u64> {
        match self {
            Self::U8 => Some(1),
            Self::U16Le | Self::U16Be => Some(2),
            Self::U32Le | Self::U32Be => Some(4),
            Self::U64Le | Self::U64Be => Some(8),
            Self::Float | Self::Str | Self::Raw => None,
        }
    }
}

impl fmt::Display for RegionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::U8 => "u8",
            Self::U16Le => "u16le",
            Self::U16Be => "u16be",
            Self::U32Le => "u32le",
            Self::U32Be => "u32be",
            Self::U64Le => "u64le",
            Self::U64Be => "u64be",
            Self::Float => "float",
            Self::Str => "str",
            Self::Raw => "raw",
        };
        f.write_str(s)
    }
}

/// A named region `[start, end)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Region {
    pub start: u64,
    pub end: u64,
    pub label: String,
    #[serde(rename = "type")]
    pub rtype: RegionType,
}

impl Region {
    pub fn len(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    pub fn contains(&self, offset: u64) -> bool {
        (self.start..self.end).contains(&offset)
    }

    /// Decode the region's current bytes into a display string.
    pub fn decode(&self, buf: &FileBuffer) -> String {
        let len = self.len().min(64 * 1024) as usize;
        let bytes = buf.get_range(self.start, len);
        decode_value(self.rtype, &bytes)
    }
}

pub fn decode_value(rtype: RegionType, bytes: &[u8]) -> String {
    macro_rules! int {
        ($t:ty, $from:ident, $n:expr) => {{
            if bytes.len() < $n {
                return format!("<need {} bytes>", $n);
            }
            let v = <$t>::$from(bytes[..$n].try_into().unwrap());
            format!("{} (0x{:X})", v, v)
        }};
    }
    match rtype {
        RegionType::U8 => int!(u8, from_le_bytes, 1),
        RegionType::U16Le => int!(u16, from_le_bytes, 2),
        RegionType::U16Be => int!(u16, from_be_bytes, 2),
        RegionType::U32Le => int!(u32, from_le_bytes, 4),
        RegionType::U32Be => int!(u32, from_be_bytes, 4),
        RegionType::U64Le => int!(u64, from_le_bytes, 8),
        RegionType::U64Be => int!(u64, from_be_bytes, 8),
        RegionType::Float => match bytes.len() {
            8.. => format!("{}", f64::from_le_bytes(bytes[..8].try_into().unwrap())),
            4.. => format!("{}", f32::from_le_bytes(bytes[..4].try_into().unwrap())),
            _ => "<need 4 or 8 bytes>".into(),
        },
        RegionType::Str => {
            let printable: String = bytes
                .iter()
                .take_while(|&&b| b != 0)
                .map(|&b| {
                    if (0x20..0x7f).contains(&b) {
                        b as char
                    } else {
                        '.'
                    }
                })
                .collect();
            format!("\"{}\"", printable)
        }
        RegionType::Raw => {
            let shown = bytes.len().min(8);
            let hex: Vec<String> = bytes[..shown].iter().map(|b| format!("{b:02X}")).collect();
            if bytes.len() > shown {
                format!("{} .. ({} bytes)", hex.join(" "), bytes.len())
            } else {
                hex.join(" ")
            }
        }
    }
}

/// `.bxa` sidecar document.
#[derive(Debug, Serialize, Deserialize)]
pub struct BxaFile {
    pub version: u32,
    pub file_md5: String,
    pub regions: Vec<Region>,
    /// Named cursor bookmarks (`m<key>` / `` `<key> ``). Optional for back-compat.
    #[serde(default)]
    pub bookmarks: BTreeMap<char, u64>,
}

pub fn sidecar_path(binary: &Path) -> PathBuf {
    let mut os = binary.as_os_str().to_owned();
    os.push(".bxa");
    PathBuf::from(os)
}

pub fn load_sidecar(binary: &Path) -> Result<Option<BxaFile>, String> {
    let path = sidecar_path(binary);
    if !path.exists() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let bxa: BxaFile =
        serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(Some(bxa))
}

pub fn save_sidecar(
    binary: &Path,
    md5: &str,
    regions: &[Region],
    bookmarks: &BTreeMap<char, u64>,
) -> Result<PathBuf, String> {
    let path = sidecar_path(binary);
    let doc = BxaFile {
        version: 1,
        file_md5: md5.to_string(),
        regions: regions.to_vec(),
        bookmarks: bookmarks.clone(),
    };
    let json = serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())?;
    std::fs::write(&path, json).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_ints_both_endians() {
        assert_eq!(decode_value(RegionType::U8, &[0xFF]), "255 (0xFF)");
        assert_eq!(
            decode_value(RegionType::U16Le, &[0x34, 0x12]),
            "4660 (0x1234)"
        );
        assert_eq!(
            decode_value(RegionType::U16Be, &[0x12, 0x34]),
            "4660 (0x1234)"
        );
        assert_eq!(
            decode_value(RegionType::U32Le, &[0x78, 0x56, 0x34, 0x12]),
            "305419896 (0x12345678)"
        );
        assert_eq!(
            decode_value(RegionType::U32Be, &[0x12, 0x34, 0x56, 0x78]),
            "305419896 (0x12345678)"
        );
        assert_eq!(
            decode_value(RegionType::U64Le, &[1, 0, 0, 0, 0, 0, 0, 0]),
            "1 (0x1)"
        );
        assert_eq!(
            decode_value(RegionType::U64Be, &[0, 0, 0, 0, 0, 0, 0, 1]),
            "1 (0x1)"
        );
    }

    #[test]
    fn decode_float_str_raw() {
        assert_eq!(
            decode_value(RegionType::Float, &1.5f32.to_le_bytes()),
            "1.5"
        );
        assert_eq!(
            decode_value(RegionType::Float, &2.5f64.to_le_bytes()),
            "2.5"
        );
        assert_eq!(decode_value(RegionType::Str, b"hi\0junk"), "\"hi\"");
        assert_eq!(decode_value(RegionType::Raw, &[0xDE, 0xAD]), "DE AD");
        assert_eq!(decode_value(RegionType::U32Le, &[0x01]), "<need 4 bytes>");
    }

    #[test]
    fn bxa_roundtrip() {
        let regions = vec![Region {
            start: 16,
            end: 20,
            label: "magic".into(),
            rtype: RegionType::U32Le,
        }];
        let dir = std::env::temp_dir().join(format!("bx-bxatest-{}", std::process::id()));
        std::fs::write(&dir, b"x").unwrap();
        let mut bookmarks = BTreeMap::new();
        bookmarks.insert('a', 0x10u64);
        bookmarks.insert('z', 0x2A0u64);
        let p = save_sidecar(&dir, "d41d8cd98f00b204e9800998ecf8427e", &regions, &bookmarks).unwrap();
        assert!(p.to_string_lossy().ends_with(".bxa"));
        let loaded = load_sidecar(&dir).unwrap().unwrap();
        assert_eq!(loaded.regions.len(), 1);
        assert_eq!(loaded.regions[0].label, "magic");
        assert_eq!(loaded.regions[0].rtype, RegionType::U32Le);
        assert_eq!(loaded.bookmarks.get(&'a'), Some(&0x10));
        assert_eq!(loaded.bookmarks.get(&'z'), Some(&0x2A0));
        std::fs::remove_file(p).unwrap();
    }

    #[test]
    fn type_parse_all() {
        for t in [
            "u8", "u16le", "u16be", "u32le", "u32be", "u64le", "u64be", "float", "str", "raw",
        ] {
            assert!(RegionType::parse(t).is_some(), "{t}");
        }
        assert!(RegionType::parse("u128").is_none());
    }
}
