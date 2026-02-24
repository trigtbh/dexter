use std::io;
use std::time::Duration;
use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers,
        MouseButton, MouseEventKind,
    },
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, BorderType, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap},
    Frame, Terminal,
};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};

// ─── Constants ───────────────────────────────────────────────────────────────

const BACKEND_URL: &str = "http://localhost:7777";
const ACCENT: Color = Color::Rgb(0, 255, 180);
const DIM: Color = Color::Rgb(80, 80, 100);
const BG: Color = Color::Rgb(10, 10, 18);
const SURFACE: Color = Color::Rgb(18, 18, 30);
const TEXT: Color = Color::Rgb(200, 200, 220);
const ERR: Color = Color::Rgb(255, 80, 80);
const WARN: Color = Color::Rgb(255, 200, 0);

// ─── Tool Definitions ────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
struct Tool {
    name: &'static str,
    description: &'static str,
    category: &'static str,
    endpoint: &'static str,
    inputs: &'static [(&'static str, &'static str)], // (label, hint)
}

const TOOLS: &[Tool] = &[
    // Encoding
    Tool {
        name: "Base64 Decode",
        description: "Decode a Base64-encoded string",
        category: "ENCODING",
        endpoint: "base64_decode",
        inputs: &[("Base64 Input", "Paste base64 string here...")],
    },
    Tool {
        name: "Base64 Encode",
        description: "Encode a string to Base64",
        category: "ENCODING",
        endpoint: "base64_encode",
        inputs: &[("Plaintext Input", "Text to encode...")],
    },
    Tool {
        name: "Hex Decode",
        description: "Decode a hex string to ASCII",
        category: "ENCODING",
        endpoint: "hex_decode",
        inputs: &[("Hex Input", "e.g. 68656c6c6f...")],
    },
    Tool {
        name: "Hex Encode",
        description: "Encode ASCII to hex",
        category: "ENCODING",
        endpoint: "hex_encode",
        inputs: &[("ASCII Input", "Text to hex-encode...")],
    },
    Tool {
        name: "Binary Decode",
        description: "Decode space-separated binary to ASCII",
        category: "ENCODING",
        endpoint: "binary_decode",
        inputs: &[("Binary Input", "e.g. 01101000 01100101 01101100...")],
    },
    Tool {
        name: "URL Decode",
        description: "Decode a URL-encoded string",
        category: "ENCODING",
        endpoint: "url_decode",
        inputs: &[("URL-encoded Input", "e.g. hello%20world...")],
    },
    // Crypto
    Tool {
        name: "ROT13",
        description: "Apply ROT13 substitution cipher",
        category: "CRYPTO",
        endpoint: "rot13",
        inputs: &[("Input Text", "Text to ROT13...")],
    },
    Tool {
        name: "Caesar Brute-force",
        description: "Try all 25 Caesar cipher shifts, scored by English frequency",
        category: "CRYPTO",
        endpoint: "caesar_brute",
        inputs: &[("Ciphertext", "Paste ciphertext here...")],
    },
    Tool {
        name: "XOR Single-byte",
        description: "Brute-force single-byte XOR key, scored by English IC",
        category: "CRYPTO",
        endpoint: "xor_brute",
        inputs: &[("Hex-encoded Ciphertext", "e.g. 1b37373331363f78...")],
    },
    Tool {
        name: "XOR with Key",
        description: "XOR hex input with a repeating hex key",
        category: "CRYPTO",
        endpoint: "xor_key",
        inputs: &[
            ("Hex Input", "e.g. 1b3a45"),
            ("Hex Key", "e.g. 2f1a"),
        ],
    },
    Tool {
        name: "RSA Decrypt (n, e, c)",
        description: "Decrypt RSA using n, e, and c",
        category: "CRYPTO",
        endpoint: "rsa_decrypt",
        inputs: &[
            ("Modulus (n)", "e.g. 0x... or 1234..."),
            ("Exponent (e)", "e.g. 65537"),
            ("Ciphertext (c)", "e.g. 0x... or 1234..."),
        ],
    },
    // Forensics
    Tool {
        name: "Strings Extract",
        description: "Extract printable ASCII strings from hex or raw input",
        category: "FORENSICS",
        endpoint: "strings_extract",
        inputs: &[("Hex or Raw Input", "Paste hex bytes or raw text...")],
    },
    Tool {
        name: "File Magic Bytes",
        description: "Identify file type from magic bytes",
        category: "FORENSICS",
        endpoint: "magic_bytes",
        inputs: &[("Hex Header (first 16+ bytes)", "e.g. ffd8ffe0...")],
    },
    Tool {
        name: "LSB Extract",
        description: "Extract LSB steganography from image (hex bytes)",
        category: "FORENSICS",
        endpoint: "lsb_extract",
        inputs: &[("Hex Bytes", "Paste hex bytes (or Ctrl+O)")],
    },
    Tool {
        name: "ZSteg",
        description: "Powerful steganography detector for PNG/BMP",
        category: "FORENSICS",
        endpoint: "zsteg",
        inputs: &[("Hex Bytes", "Paste file hex bytes (or Ctrl+O)")],
    },
    Tool {
        name: "EXIF Data",
        description: "Read/write metadata in files",
        category: "FORENSICS",
        endpoint: "exiftool",
        inputs: &[("Hex Bytes", "Paste file hex bytes (or Ctrl+O)")],
    },
    Tool {
        name: "Binwalk",
        description: "Analyze, extract and identify file signatures",
        category: "FORENSICS",
        endpoint: "binwalk",
        inputs: &[("Hex Bytes", "Paste file hex bytes (or Ctrl+O)")],
    },
    Tool {
        name: "Foremost",
        description: "Recover files from data using their headers/footers",
        category: "FORENSICS",
        endpoint: "foremost",
        inputs: &[("Hex Bytes", "Paste file hex bytes (or Ctrl+O)")],
    },
    Tool {
        name: "Steghide",
        description: "Extract data with steghide (requires password)",
        category: "FORENSICS",
        endpoint: "steghide",
        inputs: &[
            ("Hex Bytes", "Paste hex bytes (or Ctrl+O)"),
            ("Password", "Enter passphrase"),
        ],
    },
    // Hashing
    Tool {
        name: "Hash Identify",
        description: "Identify likely hash algorithm from a hash string",
        category: "HASHING",
        endpoint: "hash_identify",
        inputs: &[("Hash String", "Paste hash here...")],
    },
    Tool {
        name: "MD5 Hash",
        description: "Compute MD5 hash of input",
        category: "HASHING",
        endpoint: "md5",
        inputs: &[("Input Text", "Text to hash...")],
    },
    Tool {
        name: "SHA256 Hash",
        description: "Compute SHA256 hash of input",
        category: "HASHING",
        endpoint: "sha256",
        inputs: &[("Input Text", "Text to hash...")],
    },
];

// ─── App State ───────────────────────────────────────────────────────────────

#[derive(PartialEq, Clone, Copy)]
enum Mode {
    Ops,
    Recon,
}

#[derive(PartialEq)]
enum Focus {
    ToolList,
    Input,
    Output,
}

#[derive(PartialEq)]
enum Pane {
    Normal,
    Help,
}

struct App {
    mode: Mode,
    focus: Focus,
    pane: Pane,
    tool_list_state: ListState,
    inputs: Vec<String>,
    input_cursors: Vec<usize>,
    focused_input: usize,
    output: String,
    status: String,
    status_is_error: bool,
    backend_online: bool,
    client: Client,
    output_scroll: u16,
    search_query: String,
    searching: bool,
    filtered_indices: Vec<usize>,
    // Cached rects — updated every draw, used for mouse hit-testing
    rect_tool_list: Rect,
    rect_input: Rect,
    rect_output: Rect,
    // Actual rendered scroll offset of the tool list (tracked manually)
    list_scroll_offset: usize,
    // Output selection state (visual/select mode)
    output_selecting: bool,
    output_select_start: Option<usize>,
    output_select_end: usize,
}

impl App {
    fn new() -> Self {
        let mut list_state = ListState::default();
        list_state.select(Some(0));

        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap();

        let filtered_indices = (0..TOOLS.len()).collect();

        let mut app = App {
            mode: Mode::Ops,
            focus: Focus::ToolList,
            pane: Pane::Normal,
            tool_list_state: list_state,
            inputs: vec![String::new()],
            input_cursors: vec![0],
            focused_input: 0,
            output: String::new(),
            status: String::from("Ready — press ? for help"),
            status_is_error: false,
            backend_online: false,
            client,
            output_scroll: 0,
            search_query: String::new(),
            searching: false,
            filtered_indices,
            rect_tool_list: Rect::default(),
            rect_input: Rect::default(),
            rect_output: Rect::default(),
            list_scroll_offset: 0,
            output_selecting: false,
            output_select_start: None,
            output_select_end: 0,
        };

        app.backend_online = app.check_backend();
        app
    }

    fn check_backend(&self) -> bool {
        self.client
            .get(format!("{}/health", BACKEND_URL))
            .send()
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }

    fn selected_tool(&self) -> Option<&Tool> {
        self.tool_list_state
            .selected()
            .and_then(|i| self.filtered_indices.get(i))
            .and_then(|&real_i| TOOLS.get(real_i))
    }

    fn run_tool(&mut self) {
        if !self.backend_online {
            self.set_error("Backend offline — run: docker compose up -d");
            return;
        }

        let tool = match self.selected_tool() {
            Some(t) => t.clone(),
            None => return,
        };

        if self.inputs.iter().all(|s| s.trim().is_empty()) {
            self.set_error("All inputs are empty");
            return;
        }

        self.status = format!("Running {}...", tool.name);
        self.status_is_error = false;

        // Join multiple inputs with :: for backend compatibility
        let combined_input = self.inputs.join("::");

        let payload = RunRequest {
            tool: tool.endpoint.to_string(),
            input: combined_input,
        };

        match self
            .client
            .post(format!("{}/run", BACKEND_URL))
            .json(&payload)
            .send()
        {
            Ok(resp) => match resp.json::<RunResponse>() {
                Ok(r) => {
                    if r.success {
                        self.output = r.output;
                        self.output_scroll = 0;
                        self.status = format!("✓ {} complete", tool.name);
                        self.focus = Focus::Output;
                    } else {
                        self.set_error(&format!("Tool error: {}", r.output));
                    }
                }
                Err(e) => self.set_error(&format!("Parse error: {}", e)),
            },
            Err(e) => self.set_error(&format!("Request failed: {}", e)),
        }
    }

    fn open_file_into_input(&mut self) {
        // Only implemented for macOS using osascript choose file
        // Falls back to doing nothing if the chooser fails.
        if let Ok(output) = std::process::Command::new("osascript")
            .arg("-e")
            .arg("POSIX path of (choose file)")
            .output()
        {
            if output.status.success() {
                if let Ok(path) = String::from_utf8(output.stdout) {
                    let path = path.trim();
                    if let Ok(bytes) = std::fs::read(path) {
                        // convert bytes to hex
                        let mut s = String::with_capacity(bytes.len() * 2);
                        for b in &bytes {
                            s.push_str(&format!("{:02x}", b));
                        }
                        // Use the currently focused input field
                        if let Some(target) = self.inputs.get_mut(self.focused_input) {
                            *target = s;
                            self.input_cursors[self.focused_input] = target.len();
                        }
                        self.status = format!("Loaded {} ({} bytes)", path, bytes.len());
                        self.status_is_error = false;
                        return;
                    } else {
                        self.set_error("Failed to read chosen file");
                    }
                }
            } else {
                self.set_error("File selection cancelled");
            }
        } else {
            self.set_error("File chooser unavailable");
        }
    }

    fn set_error(&mut self, msg: &str) {
        self.status = msg.to_string();
        self.status_is_error = true;
    }

    fn update_filter(&mut self) {
        let q = self.search_query.to_lowercase();
        self.filtered_indices = (0..TOOLS.len())
            .filter(|&i| {
                let t = &TOOLS[i];
                q.is_empty()
                    || t.name.to_lowercase().contains(&q)
                    || t.category.to_lowercase().contains(&q)
                    || t.description.to_lowercase().contains(&q)
            })
            .collect();

        if !self.filtered_indices.is_empty() {
            self.tool_list_state.select(Some(0));
            self.clear_input();
        }
    }

    fn next_tool(&mut self) {
        let len = self.filtered_indices.len();
        if len == 0 { return; }
        let i = self.tool_list_state.selected().unwrap_or(0);
        self.tool_list_state.select(Some((i + 1) % len));
    }

    fn prev_tool(&mut self) {
        let len = self.filtered_indices.len();
        if len == 0 { return; }
        let i = self.tool_list_state.selected().unwrap_or(0);
        self.tool_list_state.select(Some(if i == 0 { len - 1 } else { i - 1 }));
    }

    fn insert_char(&mut self, c: char) {
        if let Some(s) = self.inputs.get_mut(self.focused_input) {
            let cursor = &mut self.input_cursors[self.focused_input];
            s.insert(*cursor, c);
            *cursor += c.len_utf8();
        }
    }

    fn delete_char(&mut self) {
        if let Some(s) = self.inputs.get_mut(self.focused_input) {
            let cursor = &mut self.input_cursors[self.focused_input];
            if *cursor > 0 {
                let prev = s[..*cursor]
                    .char_indices()
                    .last()
                    .map(|(i, _)| i)
                    .unwrap_or(0);
                s.remove(prev);
                *cursor = prev;
            }
        }
    }

    fn clear_input(&mut self) {
        if let Some(tool) = self.selected_tool() {
            let n = tool.inputs.len();
            self.inputs = vec![String::new(); n];
            self.input_cursors = vec![0; n];
            self.focused_input = 0;
        } else {
            self.inputs = vec![String::new()];
            self.input_cursors = vec![0];
            self.focused_input = 0;
        }
        self.output.clear();
        self.status = String::from("Ready");
        self.status_is_error = false;
    }

    // ── Mouse helpers ──────────────────────────────────────────────────────

    fn hit(rect: Rect, col: u16, row: u16) -> bool {
        col >= rect.x
            && col < rect.x + rect.width
            && row >= rect.y
            && row < rect.y + rect.height
    }

    /// Convert an absolute terminal row inside the tool list pane to a logical
    /// tool index and select it.
    fn click_tool_at_row(&mut self, row: u16) {
        // Build a flat map of every rendered row → Option<display_pos>
        // (None means it's a category header row, Some(i) means it's tool i)
        // This avoids any offset math — we just index directly by visible row.
        let mut row_map: Vec<Option<usize>> = Vec::new();
        let mut last_cat = "";
        for (display_pos, &real_i) in self.filtered_indices.iter().enumerate() {
            let tool = &TOOLS[real_i];
            if tool.category != last_cat {
                last_cat = tool.category;
                row_map.push(None); // category header row
            }
            row_map.push(Some(display_pos));
        }

        // The list widget scrolls by hiding the top `offset` rows.
        // visible_row is which row inside the pane was clicked (0 = first visible).
        let visible_row = row.saturating_sub(self.rect_tool_list.y + 1) as usize;
        let actual_row = visible_row + self.list_scroll_offset;

        match row_map.get(actual_row) {
            Some(Some(display_pos)) => {
                self.tool_list_state.select(Some(*display_pos));
                self.clear_input();
            }
            _ => {} // header row or out of bounds — ignore
        }
    }

    fn clamp_output_scroll(&mut self) {
        let content_len = self.output.lines().count();
        let height = self.rect_output.height.saturating_sub(2) as usize;
        if content_len <= height {
            self.output_scroll = 0;
        } else {
            let max_scroll = (content_len - height) as u16;
            if self.output_scroll > max_scroll {
                self.output_scroll = max_scroll;
            }
        }
    }

    fn handle_mouse(&mut self, col: u16, row: u16, kind: MouseEventKind) {
        match kind {
            MouseEventKind::Down(MouseButton::Left) => {
                if Self::hit(self.rect_tool_list, col, row) {
                    self.focus = Focus::ToolList;
                    self.click_tool_at_row(row);
                } else if Self::hit(self.rect_input, col, row) {
                    self.focus = Focus::Input;
                    // Switch focused input field based on click row
                    if let Some(tool) = self.selected_tool() {
                        let n = tool.inputs.len();
                        if n > 1 {
                            let rel_y = row.saturating_sub(self.rect_input.y + 1);
                            // Each input box takes roughly rect.height / n rows
                            let field_height = self.rect_input.height.saturating_sub(2) / n as u16;
                            if field_height > 0 {
                                let field_idx = (rel_y / field_height) as usize;
                                self.focused_input = field_idx.min(n - 1);
                            }
                        }
                    }
                } else if Self::hit(self.rect_output, col, row) {
                    self.focus = Focus::Output;
                }
            }
            MouseEventKind::ScrollUp => {
                if Self::hit(self.rect_tool_list, col, row) {
                    self.prev_tool();
                    self.clear_input();
                } else if Self::hit(self.rect_output, col, row) {
                    self.output_scroll = self.output_scroll.saturating_sub(3);
                }
            }
            MouseEventKind::ScrollDown => {
                if Self::hit(self.rect_tool_list, col, row) {
                    self.next_tool();
                    self.clear_input();
                } else if Self::hit(self.rect_output, col, row) {
                    self.output_scroll = self.output_scroll.saturating_add(3);
                    self.clamp_output_scroll();
                }
            }
            _ => {}
        }
    }
}

// ─── API Types ───────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct RunRequest {
    tool: String,
    input: String,
}

#[derive(Deserialize)]
struct RunResponse {
    success: bool,
    output: String,
}

// ─── Main ────────────────────────────────────────────────────────────────────

fn main() -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new();
    let result = run_app(&mut terminal, &mut app);

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if let Err(e) = result {
        eprintln!("Error: {}", e);
    }
    Ok(())
}

fn run_app<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App,
) -> io::Result<()> {
    loop {
        terminal.draw(|f| draw(f, app))?;

        if !event::poll(Duration::from_millis(250))? {
            continue;
        }

        match event::read()? {
            // ── Mouse ──────────────────────────────────────────────────────
            Event::Mouse(me) => {
                if app.pane == Pane::Help {
                    app.pane = Pane::Normal;
                    continue;
                }
                app.handle_mouse(me.column, me.row, me.kind);
            }

            // ── Keyboard ───────────────────────────────────────────────────
            Event::Key(key) => {
                if app.pane == Pane::Help {
                    app.pane = Pane::Normal;
                    continue;
                }

                // Search mode intercepts all keys
                if app.searching {
                    match key.code {
                        KeyCode::Esc => {
                            app.searching = false;
                            app.search_query.clear();
                            app.update_filter();
                        }
                        KeyCode::Enter => {
                            app.searching = false;
                            app.focus = Focus::ToolList;
                        }
                        KeyCode::Backspace => {
                            app.search_query.pop();
                            app.update_filter();
                        }
                        KeyCode::Char(c) => {
                            app.search_query.push(c);
                            app.update_filter();
                        }
                        _ => {}
                    }
                    continue;
                }

                match key.code {
                    // Quit
                    KeyCode::Char('q')
                        if key.modifiers.contains(KeyModifiers::CONTROL) =>
                    {
                        return Ok(());
                    }
                    KeyCode::Char('q') if app.focus == Focus::ToolList => return Ok(()),

                    // Help
                    KeyCode::Char('?') => app.pane = Pane::Help,

                    // Mode toggle / Input field switch
                    KeyCode::Tab => {
                        if app.focus == Focus::Input {
                            app.focused_input = (app.focused_input + 1) % app.inputs.len();
                        } else {
                            app.mode = match app.mode {
                                Mode::Ops => Mode::Recon,
                                Mode::Recon => Mode::Ops,
                            };
                            app.status = match app.mode {
                                Mode::Ops => String::from("Switched to OPS mode"),
                                Mode::Recon => String::from("Switched to RECON mode (coming soon)"),
                            };
                        }
                    }
                    KeyCode::BackTab => {
                        if app.focus == Focus::Input {
                            let n = app.inputs.len();
                            app.focused_input = if app.focused_input == 0 { n - 1 } else { app.focused_input - 1 };
                        }
                    }

                    // Search
                    KeyCode::Char('/') if app.focus == Focus::ToolList => {
                        app.searching = true;
                    }

                    // Focus cycling
                    KeyCode::Right
                        if app.focus == Focus::ToolList =>
                    {
                        app.focus = Focus::Input;
                    }
                    KeyCode::Left
                        if app.focus == Focus::Output || app.focus == Focus::Input =>
                    {
                        app.focus = Focus::ToolList;
                    }
                    KeyCode::Down if app.focus == Focus::Input => {
                        if app.focused_input + 1 < app.inputs.len() {
                            app.focused_input += 1;
                        } else {
                            app.focus = Focus::Output;
                        }
                    }
                    KeyCode::Up if app.focus == Focus::Input => {
                        if app.focused_input > 0 {
                            app.focused_input -= 1;
                        } else {
                            app.focus = Focus::ToolList;
                        }
                    }

                    // Tool navigation
                    KeyCode::Down if app.focus == Focus::ToolList => {
                        app.next_tool();
                        app.clear_input();
                    }
                    KeyCode::Up if app.focus == Focus::ToolList => {
                        app.prev_tool();
                        app.clear_input();
                    }

                    // Run tool
                    KeyCode::Enter if app.focus == Focus::Input => app.run_tool(),
                    KeyCode::Char('r') if app.focus == Focus::ToolList => {
                        app.focus = Focus::Input;
                    }

                    // Output scroll/navigation
                    KeyCode::Down if app.focus == Focus::Output => {
                        if app.output_selecting {
                            let lines_count = app.output.lines().count();
                            let max_idx = lines_count.saturating_sub(1);
                            app.output_select_end = (app.output_select_end + 1).min(max_idx);
                        } else {
                            app.output_scroll = app.output_scroll.saturating_add(1);
                            app.clamp_output_scroll();
                        }
                    }
                    KeyCode::Up if app.focus == Focus::Output => {
                        if app.output_selecting {
                            if app.output_select_end > 0 {
                                app.output_select_end = app.output_select_end.saturating_sub(1);
                            }
                        } else {
                            if app.output_scroll == 0 {
                                app.focus = Focus::Input;
                                app.focused_input = app.inputs.len().saturating_sub(1);
                            } else {
                                app.output_scroll = app.output_scroll.saturating_sub(1);
                            }
                        }
                    }

                    // Input editing
                    KeyCode::Backspace if app.focus == Focus::Input => app.delete_char(),
                    KeyCode::Char('u')
                        if app.focus == Focus::Input
                            && key.modifiers.contains(KeyModifiers::CONTROL) =>
                    {
                        app.clear_input();
                    }
                    // Ctrl+O: for FORENSICS tools, open a file and load bytes
                    KeyCode::Char('o')
                        if key.modifiers.contains(KeyModifiers::CONTROL)
                            && app.focus == Focus::Input =>
                    {
                        if let Some(tool) = app.selected_tool() {
                            if tool.category == "FORENSICS" {
                                app.open_file_into_input();
                            }
                        }
                    }
                    KeyCode::Char(c) if app.focus == Focus::Input && !key.modifiers.contains(KeyModifiers::CONTROL) => app.insert_char(c),
                    KeyCode::Esc if app.focus == Focus::Input => {
                        app.focus = Focus::ToolList;
                    }

                    // Output selection start/stop (v) and copy (Ctrl+C)
                    KeyCode::Char('v') if app.focus == Focus::Output => {
                        if !app.output.is_empty() {
                            if !app.output_selecting {
                                // start selection at top visible line
                                let start = app.output_scroll as usize;
                                app.output_selecting = true;
                                app.output_select_start = Some(start);
                                app.output_select_end = start;
                                app.status = String::from("Selection started (use ↑/↓ to expand, Ctrl+C to copy)");
                            } else {
                                app.output_selecting = false;
                                app.output_select_start = None;
                                app.status = String::from("Selection cleared");
                            }
                        }
                    }

                    KeyCode::Char('c')
                        if key.modifiers.contains(KeyModifiers::CONTROL)
                            && app.focus == Focus::Output =>
                    {
                        // Copy selection if active, otherwise copy full output
                        if app.output_selecting {
                            if let Some(start) = app.output_select_start {
                                let lines: Vec<&str> = app.output.lines().collect();
                                let a = start.min(app.output_select_end);
                                let b = start.max(app.output_select_end);
                                let sel = lines[a..=b].join("\n");
                                // copy via pbcopy on macOS
                                if let Ok(mut child) = std::process::Command::new("pbcopy").stdin(std::process::Stdio::piped()).spawn() {
                                    if let Some(mut stdin) = child.stdin.take() {
                                        use std::io::Write;
                                        let _ = stdin.write_all(sel.as_bytes());
                                    }
                                }
                                app.status = format!("Copied {} lines to clipboard", b - a + 1);
                                app.output_selecting = false;
                                app.output_select_start = None;
                            }
                        } else {
                            if !app.output.is_empty() {
                                if let Ok(mut child) = std::process::Command::new("pbcopy").stdin(std::process::Stdio::piped()).spawn() {
                                    if let Some(mut stdin) = child.stdin.take() {
                                        use std::io::Write;
                                        let _ = stdin.write_all(app.output.as_bytes());
                                    }
                                }
                                app.status = String::from("Copied output to clipboard");
                            }
                        }
                    }

                    _ => {}
                }
            }

            _ => {}
        }
    }
}

// ─── Drawing ─────────────────────────────────────────────────────────────────

// Note: draw takes &mut App so it can write back the cached pane rects
fn draw(f: &mut Frame, app: &mut App) {
    let area = f.size();

    f.render_widget(Block::default().style(Style::default().bg(BG)), area);

    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(area);

    draw_header(f, app, outer[0]);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(32), Constraint::Min(0)])
        .split(outer[1]);

    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(body[1]);

    // Cache rects every frame for mouse hit-testing
    app.rect_tool_list = body[0];
    app.rect_input = right[0];
    app.rect_output = right[1];

    draw_tool_list(f, app, body[0]);
    draw_input(f, app, right[0]);
    draw_output(f, app, right[1]);
    draw_status(f, app, outer[2]);

    if app.pane == Pane::Help {
        draw_help(f, area);
    }
}

fn draw_header(f: &mut Frame, app: &App, area: Rect) {
    let mode_label = match app.mode {
        Mode::Ops => Span::styled(
            " OPS ",
            Style::default().fg(BG).bg(ACCENT).add_modifier(Modifier::BOLD),
        ),
        Mode::Recon => Span::styled(
            " RECON ",
            Style::default().fg(BG).bg(WARN).add_modifier(Modifier::BOLD),
        ),
    };

    let backend_indicator = if app.backend_online {
        Span::styled("● ONLINE", Style::default().fg(ACCENT))
    } else {
        Span::styled("● OFFLINE", Style::default().fg(ERR))
    };

    let title_line = Line::from(vec![
        Span::styled("  DEXTER ", Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)),
        Span::styled("/ ", Style::default().fg(DIM)),
        mode_label,
        Span::raw("  "),
        Span::styled("CTF Swiss Army Knife", Style::default().fg(DIM)),
        Span::raw("   "),
        backend_indicator,
    ]);

    let header = Paragraph::new(title_line)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(DIM))
                .style(Style::default().bg(SURFACE)),
        )
        .alignment(Alignment::Left);

    f.render_widget(header, area);
}

fn draw_tool_list(f: &mut Frame, app: &mut App, area: Rect) {
    let is_focused = app.focus == Focus::ToolList;
    let border_style = if is_focused {
        Style::default().fg(ACCENT)
    } else {
        Style::default().fg(DIM)
    };

    let search_title = if app.searching {
        format!(" / {} ", app.search_query)
    } else if !app.search_query.is_empty() {
        format!(" [{}] ", app.search_query)
    } else {
        String::from(" Tools ")
    };

    let block = Block::default()
        .title(Span::styled(
            search_title,
            Style::default()
                .fg(if app.searching { WARN } else { ACCENT })
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(border_style)
        .style(Style::default().bg(SURFACE));

    let mut last_category = "";
    let mut items: Vec<ListItem> = Vec::new();

    for &real_i in &app.filtered_indices {
        let tool = &TOOLS[real_i];
        if tool.category != last_category {
            last_category = tool.category;
            items.push(ListItem::new(Line::from(vec![Span::styled(
                format!(" {} ", tool.category),
                Style::default().fg(DIM).add_modifier(Modifier::BOLD),
            )])));
        }
        items.push(ListItem::new(Line::from(vec![
            Span::raw("  "),
            Span::styled(tool.name, Style::default().fg(TEXT)),
        ])));
    }

    let list = List::new(items)
        .block(block)
        .highlight_style(
            Style::default()
                .fg(BG)
                .bg(ACCENT)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");

    // Remap selection to account for category header rows
    let mut display_state = ListState::default();
    if let Some(selected) = app.tool_list_state.selected() {
        let mut display_index = 0;
        let mut last_cat = "";
        for (display_pos, &real_i) in app.filtered_indices.iter().enumerate() {
            let tool = &TOOLS[real_i];
            if tool.category != last_cat {
                last_cat = tool.category;
                display_index += 1;
            }
            if display_pos == selected {
                display_state.select(Some(display_index));
                break;
            }
            display_index += 1;
        }
    }

    // Pin the viewport to our stored offset before rendering so that
    // clicking a tool never causes the list to scroll/jump.
    *display_state.offset_mut() = app.list_scroll_offset;

    f.render_stateful_widget(list, area, &mut display_state);
    // Sync offset back in case keyboard navigation moved it legitimately.
    app.list_scroll_offset = display_state.offset();
}

fn draw_input(f: &mut Frame, app: &App, area: Rect) {
    let is_focused = app.focus == Focus::Input;
    let border_style = if is_focused {
        Style::default().fg(ACCENT)
    } else {
        Style::default().fg(DIM)
    };

    let tool = app.selected_tool();
    let num_inputs = tool.map(|t| t.inputs.len()).unwrap_or(1);

    let block = Block::default()
        .title(Span::styled(
            " Input ",
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ))
        .title_bottom(if is_focused {
            Line::from(Span::styled(
                " Enter to run  Tab/↓ to switch fields  Ctrl+U to clear ",
                Style::default().fg(DIM),
            ))
        } else {
            Line::from(Span::styled(
                " click or l/r to focus ",
                Style::default().fg(DIM),
            ))
        })
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(border_style)
        .style(Style::default().bg(SURFACE));

    let inner_area = block.inner(area);
    f.render_widget(block, area);

    let constraints = vec![Constraint::Min(1); num_inputs];
    let input_rects = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(inner_area);

    for i in 0..num_inputs {
        let (label, hint) = tool
            .and_then(|t| t.inputs.get(i))
            .copied()
            .unwrap_or(("Input", "Select a tool..."));

        let val = app.inputs.get(i).map(|s| s.as_str()).unwrap_or("");
        let cursor = app.input_cursors.get(i).copied().unwrap_or(0);
        let field_focused = is_focused && app.focused_input == i;

        let display_text = if val.is_empty() && !field_focused {
            Text::from(Line::from(vec![
                Span::styled(format!("{}: ", label), Style::default().fg(DIM)),
                Span::styled(hint, Style::default().fg(DIM).add_modifier(Modifier::ITALIC)),
            ]))
        } else if field_focused {
            let before = &val[..cursor];
            let after = &val[cursor..];
            Text::from(Line::from(vec![
                Span::styled(format!("{}: ", label), Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)),
                Span::styled(before, Style::default().fg(TEXT)),
                Span::styled("█", Style::default().fg(ACCENT)),
                Span::styled(after, Style::default().fg(TEXT)),
            ]))
        } else {
            Text::from(Line::from(vec![
                Span::styled(format!("{}: ", label), Style::default().fg(DIM)),
                Span::styled(val, Style::default().fg(TEXT)),
            ]))
        };

        let field_block = Block::default()
            .style(if field_focused {
                Style::default().bg(Color::Rgb(25, 25, 40))
            } else {
                Style::default()
            });

        let p = Paragraph::new(display_text)
            .block(field_block)
            .wrap(Wrap { trim: false });

        f.render_widget(p, input_rects[i]);
    }
}

fn draw_output(f: &mut Frame, app: &App, area: Rect) {
    let is_focused = app.focus == Focus::Output;
    let border_style = if is_focused {
        Style::default().fg(ACCENT)
    } else {
        Style::default().fg(DIM)
    };

    let output_text = if app.output.is_empty() {
        Text::from(Line::from(Span::styled(
            "Output will appear here after running a tool...",
            Style::default().fg(DIM).add_modifier(Modifier::ITALIC),
        )))
    } else {
        let mut lines: Vec<Line> = Vec::new();
        for (idx, line) in app.output.lines().enumerate() {
            let mut style = if line.contains("picoCTF{") || line.contains("flag{") || line.contains("CTF{") {
                Style::default().fg(BG).bg(ACCENT).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(TEXT)
            };

            // Highlight selection region if present
            if app.output_selecting {
                if let Some(start) = app.output_select_start {
                    let a = start.min(app.output_select_end);
                    let b = start.max(app.output_select_end);
                    if idx >= a && idx <= b {
                        style = style.bg(Color::Rgb(50, 50, 80)).fg(ACCENT).add_modifier(Modifier::REVERSED);
                    }
                }
            }

            lines.push(Line::from(Span::styled(line.to_string(), style)));
        }
        Text::from(lines)
    };

    let output_widget = Paragraph::new(output_text)
        .block(
            Block::default()
                .title(Span::styled(
                    " Output ",
                    Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
                ))
                .title_bottom(if is_focused {
                    Line::from(vec![
                        Span::styled(" v ", Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)),
                        Span::styled("select ", Style::default().fg(DIM)),
                        Span::styled(" Ctrl+C ", Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)),
                        Span::styled("copy ", Style::default().fg(DIM)),
                        Span::styled(" ↑/↓ / scroll to nav ", Style::default().fg(DIM)),
                    ])
                } else {
                    Line::from(Span::styled(
                        " click or scroll to focus ",
                        Style::default().fg(DIM),
                    ))
                })
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(border_style)
                .style(Style::default().bg(SURFACE)),
        )
        .wrap(Wrap { trim: false })
        .scroll((app.output_scroll, 0));

    f.render_widget(output_widget, area);
}

fn draw_status(f: &mut Frame, app: &App, area: Rect) {
    let status_color = if app.status_is_error { ERR } else { ACCENT };

    let keybinds = [
        ("?", "help"),
        ("Tab", "mode"),
        ("/", "search"),
        ("arrows", "nav"),
        ("Enter", "run"),
        ("q", "quit"),
    ];

    let mut spans: Vec<Span> = vec![
        Span::raw("  "),
        Span::styled(&app.status, Style::default().fg(status_color)),
        Span::styled("   │   ", Style::default().fg(DIM)),
    ];

    for (i, (key, label)) in keybinds.iter().enumerate() {
        spans.push(Span::styled(
            key.to_string(),
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::styled(
            format!(" {}", label),
            Style::default().fg(DIM),
        ));
        if i < keybinds.len() - 1 {
            spans.push(Span::raw("  "));
        }
    }

    f.render_widget(
        Paragraph::new(Line::from(spans)).style(Style::default().bg(SURFACE)),
        area,
    );
}

fn draw_help(f: &mut Frame, area: Rect) {
    let popup_area = centered_rect(60, 72, area);
    f.render_widget(Clear, popup_area);

    let help_text = vec![
        Line::from(Span::styled(
            "  DEXTER — Keyboard & Mouse Reference",
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled("  NAVIGATION", Style::default().fg(DIM).add_modifier(Modifier::BOLD))),
        Line::from(vec![
            Span::styled("  ←               ", Style::default().fg(ACCENT)),
            Span::styled("Focus tool list", Style::default().fg(TEXT)),
        ]),
        Line::from(vec![
            Span::styled("  →               ", Style::default().fg(ACCENT)),
            Span::styled("Focus input pane", Style::default().fg(TEXT)),
        ]),
        Line::from(vec![
            Span::styled("  ↓               ", Style::default().fg(ACCENT)),
            Span::styled("Next tool / scroll output / focus output", Style::default().fg(TEXT)),
        ]),
        Line::from(vec![
            Span::styled("  ↑               ", Style::default().fg(ACCENT)),
            Span::styled("Prev tool / scroll output / focus input", Style::default().fg(TEXT)),
        ]),
        Line::from(""),
        Line::from(Span::styled("  MOUSE", Style::default().fg(DIM).add_modifier(Modifier::BOLD))),
        Line::from(vec![
            Span::styled("  Left click      ", Style::default().fg(ACCENT)),
            Span::styled("Focus pane / select tool in list", Style::default().fg(TEXT)),
        ]),
        Line::from(vec![
            Span::styled("  Scroll up/down  ", Style::default().fg(ACCENT)),
            Span::styled("Navigate tool list or scroll output", Style::default().fg(TEXT)),
        ]),
        Line::from(""),
        Line::from(Span::styled("  TOOLS", Style::default().fg(DIM).add_modifier(Modifier::BOLD))),
        Line::from(vec![
            Span::styled("  /               ", Style::default().fg(ACCENT)),
            Span::styled("Fuzzy search tools", Style::default().fg(TEXT)),
        ]),
        Line::from(vec![
            Span::styled("  Enter           ", Style::default().fg(ACCENT)),
            Span::styled("Run selected tool", Style::default().fg(TEXT)),
        ]),
        Line::from(vec![
            Span::styled("  Ctrl+U          ", Style::default().fg(ACCENT)),
            Span::styled("Clear input and output", Style::default().fg(TEXT)),
        ]),
        Line::from(vec![
            Span::styled("  Esc             ", Style::default().fg(ACCENT)),
            Span::styled("Return to tool list", Style::default().fg(TEXT)),
        ]),
        Line::from(""),
        Line::from(Span::styled("  GLOBAL", Style::default().fg(DIM).add_modifier(Modifier::BOLD))),
        Line::from(vec![
            Span::styled("  Tab             ", Style::default().fg(ACCENT)),
            Span::styled("Toggle OPS / RECON mode", Style::default().fg(TEXT)),
        ]),
        Line::from(vec![
            Span::styled("  ?               ", Style::default().fg(ACCENT)),
            Span::styled("Show this help screen", Style::default().fg(TEXT)),
        ]),
        Line::from(vec![
            Span::styled("  q / Ctrl+Q      ", Style::default().fg(ACCENT)),
            Span::styled("Quit", Style::default().fg(TEXT)),
        ]),
        Line::from(""),
        Line::from(Span::styled("  FLAGS", Style::default().fg(DIM).add_modifier(Modifier::BOLD))),
        Line::from(vec![
            Span::styled("  picoCTF{...}    ", Style::default().fg(ACCENT)),
            Span::styled("Auto-highlighted in output pane", Style::default().fg(TEXT)),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "  Press any key or click to close",
            Style::default().fg(DIM).add_modifier(Modifier::ITALIC),
        )),
    ];

    let help = Paragraph::new(help_text)
        .block(
            Block::default()
                .title(Span::styled(
                    " Help ",
                    Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
                ))
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(ACCENT))
                .style(Style::default().bg(SURFACE)),
        )
        .wrap(Wrap { trim: true });

    f.render_widget(help, popup_area);
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}