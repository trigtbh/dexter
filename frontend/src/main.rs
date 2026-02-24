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
    input_label: &'static str,
    input_hint: &'static str,
}

const TOOLS: &[Tool] = &[
    // Encoding
    Tool {
        name: "Base64 Decode",
        description: "Decode a Base64-encoded string",
        category: "ENCODING",
        endpoint: "base64_decode",
        input_label: "Base64 Input",
        input_hint: "Paste base64 string here...",
    },
    Tool {
        name: "Base64 Encode",
        description: "Encode a string to Base64",
        category: "ENCODING",
        endpoint: "base64_encode",
        input_label: "Plaintext Input",
        input_hint: "Text to encode...",
    },
    Tool {
        name: "Hex Decode",
        description: "Decode a hex string to ASCII",
        category: "ENCODING",
        endpoint: "hex_decode",
        input_label: "Hex Input",
        input_hint: "e.g. 68656c6c6f...",
    },
    Tool {
        name: "Hex Encode",
        description: "Encode ASCII to hex",
        category: "ENCODING",
        endpoint: "hex_encode",
        input_label: "ASCII Input",
        input_hint: "Text to hex-encode...",
    },
    Tool {
        name: "Binary Decode",
        description: "Decode space-separated binary to ASCII",
        category: "ENCODING",
        endpoint: "binary_decode",
        input_label: "Binary Input",
        input_hint: "e.g. 01101000 01100101 01101100...",
    },
    Tool {
        name: "URL Decode",
        description: "Decode a URL-encoded string",
        category: "ENCODING",
        endpoint: "url_decode",
        input_label: "URL-encoded Input",
        input_hint: "e.g. hello%20world...",
    },
    // Crypto
    Tool {
        name: "ROT13",
        description: "Apply ROT13 substitution cipher",
        category: "CRYPTO",
        endpoint: "rot13",
        input_label: "Input Text",
        input_hint: "Text to ROT13...",
    },
    Tool {
        name: "Caesar Brute-force",
        description: "Try all 25 Caesar cipher shifts, scored by English frequency",
        category: "CRYPTO",
        endpoint: "caesar_brute",
        input_label: "Ciphertext",
        input_hint: "Paste ciphertext here...",
    },
    Tool {
        name: "XOR Single-byte",
        description: "Brute-force single-byte XOR key, scored by English IC",
        category: "CRYPTO",
        endpoint: "xor_brute",
        input_label: "Hex-encoded Ciphertext",
        input_hint: "e.g. 1b37373331363f78...",
    },
    Tool {
        name: "XOR with Key",
        description: "XOR hex input with a repeating hex key",
        category: "CRYPTO",
        endpoint: "xor_key",
        input_label: "Hex Input :: Hex Key",
        input_hint: "e.g. 1b3a45::2f1a...",
    },
    // Forensics
    Tool {
        name: "Strings Extract",
        description: "Extract printable ASCII strings from hex or raw input",
        category: "FORENSICS",
        endpoint: "strings_extract",
        input_label: "Hex or Raw Input",
        input_hint: "Paste hex bytes or raw text...",
    },
    Tool {
        name: "File Magic Bytes",
        description: "Identify file type from magic bytes",
        category: "FORENSICS",
        endpoint: "magic_bytes",
        input_label: "Hex Header (first 16+ bytes)",
        input_hint: "e.g. ffd8ffe0...",
    },
    Tool {
        name: "LSB Extract",
        description: "Extract LSB steganography from image (path in /workspace)",
        category: "FORENSICS",
        endpoint: "lsb_extract",
        input_label: "Image Path (in /workspace)",
        input_hint: "e.g. /workspace/challenge.png",
    },
    // Hashing
    Tool {
        name: "Hash Identify",
        description: "Identify likely hash algorithm from a hash string",
        category: "HASHING",
        endpoint: "hash_identify",
        input_label: "Hash String",
        input_hint: "Paste hash here...",
    },
    Tool {
        name: "MD5 Hash",
        description: "Compute MD5 hash of input",
        category: "HASHING",
        endpoint: "md5",
        input_label: "Input Text",
        input_hint: "Text to hash...",
    },
    Tool {
        name: "SHA256 Hash",
        description: "Compute SHA256 hash of input",
        category: "HASHING",
        endpoint: "sha256",
        input_label: "Input Text",
        input_hint: "Text to hash...",
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
    input: String,
    input_cursor: usize,
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
            input: String::new(),
            input_cursor: 0,
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

        if self.input.trim().is_empty() {
            self.set_error("Input is empty");
            return;
        }

        self.status = format!("Running {}...", tool.name);
        self.status_is_error = false;

        let payload = RunRequest {
            tool: tool.endpoint.to_string(),
            input: self.input.clone(),
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
        self.input.insert(self.input_cursor, c);
        self.input_cursor += c.len_utf8();
    }

    fn delete_char(&mut self) {
        if self.input_cursor > 0 {
            let prev = self.input[..self.input_cursor]
                .char_indices()
                .last()
                .map(|(i, _)| i)
                .unwrap_or(0);
            self.input.remove(prev);
            self.input_cursor = prev;
        }
    }

    fn clear_input(&mut self) {
        self.input.clear();
        self.input_cursor = 0;
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

    fn handle_mouse(&mut self, col: u16, row: u16, kind: MouseEventKind) {
        match kind {
            MouseEventKind::Down(MouseButton::Left) => {
                if Self::hit(self.rect_tool_list, col, row) {
                    self.focus = Focus::ToolList;
                    self.click_tool_at_row(row);
                } else if Self::hit(self.rect_input, col, row) {
                    self.focus = Focus::Input;
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

                    // Mode toggle
                    KeyCode::Tab => {
                        app.mode = match app.mode {
                            Mode::Ops => Mode::Recon,
                            Mode::Recon => Mode::Ops,
                        };
                        app.status = match app.mode {
                            Mode::Ops => String::from("Switched to OPS mode"),
                            Mode::Recon => String::from("Switched to RECON mode (coming soon)"),
                        };
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
                        app.focus = Focus::Output;
                    }
                    KeyCode::Up if app.focus == Focus::Output => {
                        app.focus = Focus::Input;
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

                    // Output scroll
                    KeyCode::Down if app.focus == Focus::Output => {
                        app.output_scroll = app.output_scroll.saturating_add(1);
                    }
                    KeyCode::Up if app.focus == Focus::Output => {
                        app.output_scroll = app.output_scroll.saturating_sub(1);
                    }

                    // Input editing
                    KeyCode::Char(c) if app.focus == Focus::Input => app.insert_char(c),
                    KeyCode::Backspace if app.focus == Focus::Input => app.delete_char(),
                    KeyCode::Char('u')
                        if app.focus == Focus::Input
                            && key.modifiers.contains(KeyModifiers::CONTROL) =>
                    {
                        app.clear_input();
                    }
                    KeyCode::Esc if app.focus == Focus::Input => {
                        app.focus = Focus::ToolList;
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

    let (label, hint) = app
        .selected_tool()
        .map(|t| (t.input_label, t.input_hint))
        .unwrap_or(("Input", "Select a tool from the left..."));

    let display_text = if app.input.is_empty() && !is_focused {
        Text::from(Line::from(Span::styled(
            hint,
            Style::default().fg(DIM).add_modifier(Modifier::ITALIC),
        )))
    } else if is_focused {
        let before = &app.input[..app.input_cursor];
        let after = &app.input[app.input_cursor..];
        Text::from(Line::from(vec![
            Span::styled(before, Style::default().fg(TEXT)),
            Span::styled("█", Style::default().fg(ACCENT)),
            Span::styled(after, Style::default().fg(TEXT)),
        ]))
    } else {
        Text::from(Line::from(Span::styled(&app.input, Style::default().fg(TEXT))))
    };

    let input_widget = Paragraph::new(display_text)
        .block(
            Block::default()
                .title(Span::styled(
                    format!(" {} ", label),
                    Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
                ))
                .title_bottom(if is_focused {
                    Line::from(Span::styled(
                        " Enter to run  Ctrl+U to clear  Esc to nav ",
                        Style::default().fg(DIM),
                    ))
                } else {
                    Line::from(Span::styled(
                        " click or l to focus ",
                        Style::default().fg(DIM),
                    ))
                })
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(border_style)
                .style(Style::default().bg(SURFACE)),
        )
        .wrap(Wrap { trim: false });

    f.render_widget(input_widget, area);
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
        for line in app.output.lines() {
            if line.contains("picoCTF{") || line.contains("flag{") || line.contains("CTF{") {
                lines.push(Line::from(Span::styled(
                    line.to_string(),
                    Style::default()
                        .fg(BG)
                        .bg(ACCENT)
                        .add_modifier(Modifier::BOLD),
                )));
            } else {
                lines.push(Line::from(Span::styled(
                    line.to_string(),
                    Style::default().fg(TEXT),
                )));
            }
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
                    Line::from(Span::styled(
                        " j/k or scroll to navigate ",
                        Style::default().fg(DIM),
                    ))
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