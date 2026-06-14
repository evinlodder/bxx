mod analysis;
mod annotations;
mod app;
mod bridge;
mod buffer;
mod commands;
mod config;
mod diff;
mod export;
mod inspector;
mod marks;
mod search;
mod structs;
mod transform;
mod ui;

use std::path::PathBuf;
use std::process::ExitCode;

use app::App;
use config::Config;

const USAGE: &str = "usage: bx <file>... [--diff] [--batch]
  bx file.bin                 open in the TUI
  bx a.bin b.bin c.bin        open multiple files as tabs (gt/gT to switch)
  bx --diff a.bin b.bin       open with a side-by-side diff
  bx file.bin --batch         print file info, magic hits and headers; exit";

fn main() -> ExitCode {
    let mut files: Vec<PathBuf> = Vec::new();
    let mut batch = false;
    let mut diff = false;
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--batch" => batch = true,
            "--diff" => diff = true,
            "-h" | "--help" => {
                println!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            _ => files.push(PathBuf::from(arg)),
        }
    }
    let Some(first) = files.first() else {
        eprintln!("{USAGE}");
        return ExitCode::FAILURE;
    };
    if diff && files.len() != 2 {
        eprintln!("--diff needs exactly two files\n{USAGE}");
        return ExitCode::FAILURE;
    }

    let (config, rc_warnings) = Config::load();
    let mut app = match App::new(first, config) {
        Ok(app) => app,
        Err(e) => {
            eprintln!("bx: {e}");
            return ExitCode::FAILURE;
        }
    };
    for w in rc_warnings {
        app.output_lines.push(w);
    }
    let (pipelines, pipe_warnings) = transform::load_pipelines();
    app.pipelines = pipelines;
    for w in pipe_warnings {
        app.output_lines.push(w);
    }
    if diff {
        if let Err(e) = app.start_diff(&files[1]) {
            eprintln!("bx: {e}");
            return ExitCode::FAILURE;
        }
    } else {
        for f in &files[1..] {
            if let Err(e) = app.open_file(f) {
                eprintln!("bx: {e}");
                return ExitCode::FAILURE;
            }
        }
        app.active = 0; // focus the first file
    }

    if batch {
        for i in 0..app.docs.len() {
            app.active = i;
            if app.docs.len() > 1 {
                println!("===== {} =====", app.buf.path.display());
            }
            for line in app.info_lines() {
                println!("{line}");
            }
            if app.diff_buf.is_some() {
                println!();
                println!("diff hunks: {}", app.diff_hunks.len());
                for h in app.diff_hunks.iter().take(100) {
                    println!("  0x{:08X}..0x{:08X}  {:?}", h.start, h.end, h.kind);
                }
            }
            if app.docs.len() > 1 {
                println!();
            }
        }
        return ExitCode::SUCCESS;
    }

    let mut terminal = ratatui::init();
    let result = run(&mut terminal, &mut app);
    ratatui::restore();
    if let Err(e) = result {
        eprintln!("bx: {e}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

fn run(terminal: &mut ratatui::DefaultTerminal, app: &mut App) -> std::io::Result<()> {
    while !app.quit {
        terminal.draw(|frame| ui::draw(frame, app))?;
        let ev = crossterm::event::read()?;
        app.handle_event(ev);
    }
    Ok(())
}
