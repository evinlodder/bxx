//! `~/.bxrc` configuration: simple `key = value` lines, `#` comments.

use ratatui::style::Color;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnnoPanePos {
    Left,
    Right,
    Off,
}

#[derive(Debug, Clone)]
pub struct Config {
    /// Bytes per hex row.
    pub columns: usize,
    pub anno_pane: AnnoPanePos,
    /// Width of the annotation/analysis side pane in cells.
    pub anno_width: u16,
    /// Show the file-overview minimap strip on the right of the hex view.
    pub minimap: bool,
    pub color_annotation: Color,
    pub color_cursor: Color,
    pub color_selection: Color,
    pub color_search: Color,
    pub color_diff_changed: Color,
    pub color_diff_added: Color,
    pub color_diff_removed: Color,
    pub color_heuristic: Color,
    pub color_modified: Color,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            columns: 16,
            anno_pane: AnnoPanePos::Right,
            anno_width: 44,
            minimap: true,
            color_annotation: Color::Cyan,
            color_cursor: Color::Yellow,
            color_selection: Color::Blue,
            color_search: Color::Green,
            color_diff_changed: Color::Yellow,
            color_diff_added: Color::Green,
            color_diff_removed: Color::Red,
            color_heuristic: Color::Magenta,
            color_modified: Color::LightRed,
        }
    }
}

fn parse_color(s: &str) -> Option<Color> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix('#') {
        if hex.len() == 6
            && let Ok(v) = u32::from_str_radix(hex, 16)
        {
            return Some(Color::Rgb((v >> 16) as u8, (v >> 8) as u8, v as u8));
        }
        return None;
    }
    match s.to_ascii_lowercase().as_str() {
        "black" => Some(Color::Black),
        "red" => Some(Color::Red),
        "green" => Some(Color::Green),
        "yellow" => Some(Color::Yellow),
        "blue" => Some(Color::Blue),
        "magenta" => Some(Color::Magenta),
        "cyan" => Some(Color::Cyan),
        "gray" | "grey" => Some(Color::Gray),
        "darkgray" | "darkgrey" => Some(Color::DarkGray),
        "lightred" => Some(Color::LightRed),
        "lightgreen" => Some(Color::LightGreen),
        "lightyellow" => Some(Color::LightYellow),
        "lightblue" => Some(Color::LightBlue),
        "lightmagenta" => Some(Color::LightMagenta),
        "lightcyan" => Some(Color::LightCyan),
        "white" => Some(Color::White),
        _ => None,
    }
}

impl Config {
    pub fn rc_path() -> Option<PathBuf> {
        std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".bxrc"))
    }

    /// Load `~/.bxrc`, falling back to defaults for missing/invalid entries.
    /// Returns the config plus any warnings about lines it couldn't parse.
    pub fn load() -> (Self, Vec<String>) {
        let mut cfg = Self::default();
        let mut warnings = Vec::new();
        let Some(path) = Self::rc_path() else {
            return (cfg, warnings);
        };
        let Ok(text) = std::fs::read_to_string(&path) else {
            return (cfg, warnings);
        };
        for (lineno, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                warnings.push(format!(".bxrc:{}: expected key = value", lineno + 1));
                continue;
            };
            let (key, value) = (key.trim(), value.trim());
            let ok = match key {
                "columns" => value
                    .parse::<usize>()
                    .ok()
                    .filter(|&c| (1..=64).contains(&c))
                    .map(|c| cfg.columns = c)
                    .is_some(),
                "anno_pane" => match value {
                    "left" => {
                        cfg.anno_pane = AnnoPanePos::Left;
                        true
                    }
                    "right" => {
                        cfg.anno_pane = AnnoPanePos::Right;
                        true
                    }
                    "off" => {
                        cfg.anno_pane = AnnoPanePos::Off;
                        true
                    }
                    _ => false,
                },
                "anno_width" => value
                    .parse::<u16>()
                    .ok()
                    .filter(|&w| w >= 20)
                    .map(|w| cfg.anno_width = w)
                    .is_some(),
                "minimap" => match value {
                    "on" | "true" | "yes" => {
                        cfg.minimap = true;
                        true
                    }
                    "off" | "false" | "no" => {
                        cfg.minimap = false;
                        true
                    }
                    _ => false,
                },
                _ => {
                    if let Some(color_key) = key.strip_prefix("color.") {
                        match (color_key, parse_color(value)) {
                            ("annotation", Some(c)) => {
                                cfg.color_annotation = c;
                                true
                            }
                            ("cursor", Some(c)) => {
                                cfg.color_cursor = c;
                                true
                            }
                            ("selection", Some(c)) => {
                                cfg.color_selection = c;
                                true
                            }
                            ("search", Some(c)) => {
                                cfg.color_search = c;
                                true
                            }
                            ("diff_changed", Some(c)) => {
                                cfg.color_diff_changed = c;
                                true
                            }
                            ("diff_added", Some(c)) => {
                                cfg.color_diff_added = c;
                                true
                            }
                            ("diff_removed", Some(c)) => {
                                cfg.color_diff_removed = c;
                                true
                            }
                            ("heuristic", Some(c)) => {
                                cfg.color_heuristic = c;
                                true
                            }
                            ("modified", Some(c)) => {
                                cfg.color_modified = c;
                                true
                            }
                            _ => false,
                        }
                    } else {
                        false
                    }
                }
            };
            if !ok {
                warnings.push(format!(".bxrc:{}: bad entry '{}'", lineno + 1, line));
            }
        }
        (cfg, warnings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn color_parsing() {
        assert_eq!(parse_color("cyan"), Some(Color::Cyan));
        assert_eq!(parse_color("#ff8000"), Some(Color::Rgb(255, 128, 0)));
        assert_eq!(parse_color("notacolor"), None);
    }
}
