//! JSON report export: file info + annotated regions with parsed values.

use serde::Serialize;
use std::path::Path;

use crate::annotations::Region;
use crate::buffer::FileBuffer;

#[derive(Serialize)]
struct ReportRegion<'a> {
    start: u64,
    end: u64,
    label: &'a str,
    #[serde(rename = "type")]
    rtype: String,
    value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<String>,
}

#[derive(Serialize)]
struct Report<'a> {
    file: String,
    size: u64,
    md5: &'a str,
    entropy: f64,
    detected_type: &'a str,
    regions: Vec<ReportRegion<'a>>,
}

pub struct FileInfo {
    pub size: u64,
    pub md5: String,
    pub entropy: f64,
    pub detected_type: String,
}

pub fn write_report(
    out: &Path,
    buf: &FileBuffer,
    info: &FileInfo,
    regions: &[Region],
) -> Result<(), String> {
    let report = Report {
        file: buf.path.display().to_string(),
        size: info.size,
        md5: &info.md5,
        entropy: info.entropy,
        detected_type: &info.detected_type,
        regions: regions
            .iter()
            .map(|r| ReportRegion {
                start: r.start,
                end: r.end,
                label: &r.label,
                rtype: r.rtype.to_string(),
                value: r.decode(buf),
                note: r.note.clone(),
            })
            .collect(),
    };
    let json = serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?;
    std::fs::write(out, json).map_err(|e| format!("{}: {e}", out.display()))
}
