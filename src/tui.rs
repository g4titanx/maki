//! Maki's terminal user interface.

use std::{
    borrow::Cow,
    fs::{self, OpenOptions},
    io::{self, Write},
    path::Path,
};

use crossterm::{
    event::{
        self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, KeyboardEnhancementFlags,
        PopKeyboardEnhancementFlags, PushKeyboardEnhancementFlags,
    },
    execute, terminal,
};
use image::GenericImageView;
use maki::{DEFAULT_MAX_SECRET_SIZE, protect_with_limit, recover_with_limit};
use ratatui::{
    DefaultTerminal, Frame,
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, List, ListItem, ListState, Paragraph, Wrap},
};
use zeroize::Zeroizing;

const SPLASH_IMAGE: &[u8] = include_bytes!("../public/Maki's_Shiranui-Gata.webp");
const TAGLINE: &str = "Experience Maki's Shiranui Gata!";
const SPLASH_MAX_WIDTH: u16 = 84;
const BRAILLE_DOT_MASKS: [[u8; 2]; 4] = [[0x01, 0x08], [0x02, 0x10], [0x04, 0x20], [0x40, 0x80]];
const BAYER_MATRIX: [[u8; 4]; 4] = [[0, 8, 2, 10], [12, 4, 14, 6], [3, 11, 1, 9], [15, 7, 13, 5]];

pub fn run() -> io::Result<()> {
    let splash_image = image::load_from_memory_with_format(SPLASH_IMAGE, image::ImageFormat::WebP)
        .map_err(io::Error::other)?;
    let splash_dimensions = splash_image.dimensions();
    let splash_image = splash_image.to_rgba8();
    let cell_aspect = terminal_cell_aspect();

    ratatui::run(|terminal| {
        let _keyboard_enhancement = KeyboardEnhancement::enable()?;
        App::new(splash_image, splash_dimensions, cell_aspect).run(terminal)
    })
}

struct KeyboardEnhancement {
    enabled: bool,
}

impl KeyboardEnhancement {
    fn enable() -> io::Result<Self> {
        #[cfg(not(windows))]
        {
            execute!(
                io::stdout(),
                PushKeyboardEnhancementFlags(KeyboardEnhancementFlags::DISAMBIGUATE_ESCAPE_CODES)
            )?;
            Ok(Self { enabled: true })
        }

        #[cfg(windows)]
        {
            Ok(Self { enabled: false })
        }
    }
}

impl Drop for KeyboardEnhancement {
    fn drop(&mut self) {
        if self.enabled {
            let _ = execute!(io::stdout(), PopKeyboardEnhancementFlags);
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Screen {
    Splash,
    Home,
    ContentSource,
    ContentInput,
    PasswordSource,
    PasswordInput,
    Limit,
    Working,
    Result,
    SavePath,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Operation {
    Protect,
    Recover,
}

impl Operation {
    const fn name(self) -> &'static str {
        match self {
            Self::Protect => "Protect",
            Self::Recover => "Recover",
        }
    }

    const fn content_name(self) -> &'static str {
        match self {
            Self::Protect => "secret",
            Self::Recover => "encrypted text",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum InputSource {
    Typed,
    File,
}

enum ResultContent {
    Encrypted(String),
    Recovered(Zeroizing<Vec<u8>>),
}

struct App {
    screen: Screen,
    operation: Option<Operation>,
    content_source: Option<InputSource>,
    password_source: Option<InputSource>,
    selected: usize,
    editor: Zeroizing<String>,
    content: Zeroizing<Vec<u8>>,
    password: Zeroizing<Vec<u8>>,
    max_secret_size: usize,
    result: Option<ResultContent>,
    reveal_input: bool,
    reveal_result: bool,
    overwrite_pending: bool,
    status: Option<String>,
    exit: bool,
    splash_image: image::RgbaImage,
    splash_dimensions: (u32, u32),
    cell_aspect: CellAspect,
}

impl App {
    fn new(
        splash_image: image::RgbaImage,
        splash_dimensions: (u32, u32),
        cell_aspect: CellAspect,
    ) -> Self {
        Self {
            screen: Screen::Splash,
            operation: None,
            content_source: None,
            password_source: None,
            selected: 0,
            editor: empty_editor(),
            content: Zeroizing::new(Vec::new()),
            password: Zeroizing::new(Vec::new()),
            max_secret_size: DEFAULT_MAX_SECRET_SIZE,
            result: None,
            reveal_input: false,
            reveal_result: false,
            overwrite_pending: false,
            status: None,
            exit: false,
            splash_image,
            splash_dimensions,
            cell_aspect,
        }
    }

    fn run(&mut self, terminal: &mut DefaultTerminal) -> io::Result<()> {
        while !self.exit {
            terminal.draw(|frame| self.draw(frame))?;

            if self.screen == Screen::Working {
                self.execute_operation();
                continue;
            }

            self.handle_event(event::read()?);
        }
        Ok(())
    }

    fn draw(&mut self, frame: &mut Frame) {
        match self.screen {
            Screen::Splash => self.draw_splash(frame),
            Screen::Home => self.draw_home(frame),
            Screen::ContentSource => self.draw_content_source(frame),
            Screen::ContentInput => self.draw_content_input(frame),
            Screen::PasswordSource => self.draw_password_source(frame),
            Screen::PasswordInput => self.draw_password_input(frame),
            Screen::Limit => self.draw_limit(frame),
            Screen::Working => self.draw_working(frame),
            Screen::Result => self.draw_result(frame),
            Screen::SavePath => self.draw_save_path(frame),
        }
    }

    fn draw_splash(&mut self, frame: &mut Frame) {
        let area = frame.area();
        if area.width < 36 || area.height < 12 {
            frame.render_widget(
                Paragraph::new("Maki needs a terminal of at least 36 × 12 cells.")
                    .alignment(Alignment::Center)
                    .wrap(Wrap { trim: true }),
                area,
            );
            return;
        }

        let splash = splash_layout(area, self.splash_dimensions, self.cell_aspect);
        render_braille(frame, &self.splash_image, splash.image);
        frame.render_widget(
            Paragraph::new(TAGLINE)
                .style(Style::new().fg(Color::White).add_modifier(Modifier::BOLD))
                .alignment(Alignment::Center),
            splash.tagline,
        );
        frame.render_widget(
            Paragraph::new("Enter  Continue    Q  Quit")
                .style(Style::new().fg(Color::DarkGray))
                .alignment(Alignment::Center),
            splash.help,
        );
    }

    fn draw_home(&self, frame: &mut Frame) {
        self.draw_menu(
            frame,
            "Maki",
            &[
                ("Protect", "Encrypt a secret"),
                ("Recover", "Recover a secret"),
                ("Quit", "Leave Maki"),
            ],
            "↑/↓  Select    Enter  Continue    Q  Quit",
        );
    }

    fn draw_content_source(&self, frame: &mut Frame) {
        let operation = self.operation.expect("operation selected");
        let title = format!("{} · {} input", operation.name(), operation.content_name());
        self.draw_menu(
            frame,
            &title,
            &[
                ("Type or paste", "Enter content inside Maki"),
                ("Read from file", "Load the exact bytes from a path"),
            ],
            "↑/↓  Select    Enter  Continue    Esc  Home",
        );
    }

    fn draw_password_source(&self, frame: &mut Frame) {
        self.draw_menu(
            frame,
            "Password input",
            &[
                ("Type or paste", "Hidden by default; reveal is optional"),
                ("Read from file", "Use every byte in the selected file"),
            ],
            "↑/↓  Select    Enter  Continue    Esc  Home",
        );
    }

    fn draw_menu(&self, frame: &mut Frame, title: &str, items: &[(&str, &str)], help: &str) {
        let area = centered_area(frame.area(), 68, (items.len() as u16).saturating_add(6));
        let block = Block::bordered().title(format!(" {title} "));
        let inner = block.inner(area);
        frame.render_widget(block, area);

        let [list_area, help_area] =
            Layout::vertical([Constraint::Fill(1), Constraint::Length(2)]).areas(inner);
        let list_items = items.iter().map(|(name, description)| {
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!(" {name:<18}"),
                    Style::new().add_modifier(Modifier::BOLD),
                ),
                Span::styled(*description, Style::new().fg(Color::DarkGray)),
            ]))
        });
        let list = List::new(list_items)
            .highlight_symbol("›")
            .highlight_style(Style::new().fg(Color::Blue));
        let mut state = ListState::default().with_selected(Some(self.selected));
        frame.render_stateful_widget(list, list_area, &mut state);
        frame.render_widget(
            Paragraph::new(help)
                .style(Style::new().fg(Color::DarkGray))
                .alignment(Alignment::Center),
            help_area,
        );
    }

    fn draw_content_input(&self, frame: &mut Frame) {
        let operation = self.operation.expect("operation selected");
        let source = self.content_source.expect("content source selected");
        let title = match source {
            InputSource::Typed => {
                format!("{} · Enter {}", operation.name(), operation.content_name())
            }
            InputSource::File => format!(
                "{} · {} file path",
                operation.name(),
                operation.content_name()
            ),
        };

        let display = match (operation, source, self.reveal_input) {
            (Operation::Protect, InputSource::Typed, false) => Cow::Owned(format!(
                "Secret hidden · {} bytes entered",
                self.editor.len()
            )),
            _ => Cow::Borrowed(self.editor.as_str()),
        };
        let help = match source {
            InputSource::Typed => {
                if operation == Operation::Protect {
                    "Shift+Enter  New line    Enter  Continue    Ctrl+R  Reveal/hide    Esc  Home"
                } else {
                    "Shift+Enter  New line    Enter  Continue    Esc  Home"
                }
            }
            InputSource::File => "Enter  Load file    Esc  Home",
        };

        self.draw_editor(frame, &title, display.as_ref(), help, false);
    }

    fn draw_password_input(&self, frame: &mut Frame) {
        let source = self.password_source.expect("password source selected");
        let (display, help) = match source {
            InputSource::Typed if !self.reveal_input => (
                format!("Password hidden · {} bytes entered", self.editor.len()),
                "Shift+Enter  New line    Enter  Continue    Ctrl+R  Reveal/hide    Esc  Home",
            ),
            InputSource::Typed => (
                self.editor.to_string(),
                "Shift+Enter  New line    Enter  Continue    Ctrl+R  Reveal/hide    Esc  Home",
            ),
            InputSource::File => (
                self.editor.to_string(),
                "Enter  Load exact file bytes    Esc  Home",
            ),
        };
        self.draw_editor(frame, "Password", &display, help, true);
    }

    fn draw_limit(&self, frame: &mut Frame) {
        self.draw_editor(
            frame,
            "Maximum secret size",
            self.editor.as_str(),
            "Enter  Continue    Esc  Home",
            false,
        );
    }

    fn draw_editor(
        &self,
        frame: &mut Frame,
        title: &str,
        display: &str,
        help: &str,
        password_notice: bool,
    ) {
        let area = centered_area(frame.area(), 84, 18);
        let block = Block::bordered().title(format!(" {title} "));
        let inner = block.inner(area);
        frame.render_widget(block, area);

        let [notice_area, editor_area, status_area, help_area] = Layout::vertical([
            Constraint::Length(2),
            Constraint::Fill(1),
            Constraint::Length(2),
            Constraint::Length(2),
        ])
        .areas(inner);

        let notice = if self.screen == Screen::Limit {
            format!("Recommended: {DEFAULT_MAX_SECRET_SIZE} bytes. Enter a positive byte limit.")
        } else if password_notice {
            "Typed passwords are hidden by default. Password files are read without modification."
                .to_owned()
        } else {
            String::new()
        };
        frame.render_widget(
            Paragraph::new(notice).style(Style::new().fg(Color::DarkGray)),
            notice_area,
        );
        frame.render_widget(
            Paragraph::new(display)
                .block(Block::bordered())
                .wrap(Wrap { trim: false }),
            editor_area,
        );
        self.draw_status(frame, status_area);
        frame.render_widget(
            Paragraph::new(help)
                .style(Style::new().fg(Color::DarkGray))
                .alignment(Alignment::Center),
            help_area,
        );
    }

    fn draw_working(&self, frame: &mut Frame) {
        let area = centered_area(frame.area(), 54, 7);
        frame.render_widget(
            Paragraph::new(vec![
                Line::from("Maki is working…"),
                Line::from(""),
                Line::from("Argon2id is using its 2 GiB memory profile."),
            ])
            .block(Block::bordered().title(" Please wait "))
            .alignment(Alignment::Center),
            area,
        );
    }

    fn draw_result(&self, frame: &mut Frame) {
        let area = centered_area(frame.area(), 92, 24);
        let title = match self.operation {
            Some(Operation::Protect) => " Protected text ",
            Some(Operation::Recover) => " Recovered content ",
            None => " Result ",
        };
        let block = Block::bordered().title(title);
        let inner = block.inner(area);
        frame.render_widget(block, area);
        let [content_area, status_area, help_area] = Layout::vertical([
            Constraint::Fill(1),
            Constraint::Length(2),
            Constraint::Length(2),
        ])
        .areas(inner);

        match &self.result {
            Some(ResultContent::Encrypted(text)) => frame.render_widget(
                Paragraph::new(text.as_str()).wrap(Wrap { trim: false }),
                content_area,
            ),
            Some(ResultContent::Recovered(bytes)) if !self.reveal_result => {
                frame.render_widget(
                    Paragraph::new(format!(
                        "Recovered {} bytes. Content is hidden.",
                        bytes.len()
                    ))
                    .alignment(Alignment::Center),
                    content_area,
                );
            }
            Some(ResultContent::Recovered(bytes)) => match std::str::from_utf8(bytes) {
                Ok(text) => frame.render_widget(
                    Paragraph::new(text).wrap(Wrap { trim: false }),
                    content_area,
                ),
                Err(_) => frame.render_widget(
                    Paragraph::new(format!(
                        "Recovered {} bytes of non-UTF-8 content. Save it to a file.",
                        bytes.len()
                    ))
                    .alignment(Alignment::Center),
                    content_area,
                ),
            },
            None => frame.render_widget(
                Paragraph::new("The operation did not complete.").alignment(Alignment::Center),
                content_area,
            ),
        }

        self.draw_status(frame, status_area);
        let help = match (&self.operation, &self.result) {
            (Some(Operation::Recover), Some(ResultContent::Recovered(_))) => {
                "R  Reveal/hide    S  Save    P  Retry password    Esc  Home"
            }
            (Some(Operation::Recover), _) => "P  Retry password    Esc  Home",
            (Some(Operation::Protect), Some(ResultContent::Encrypted(_))) => {
                "S  Save    P  Retry password    L  Change limit    Esc  Home"
            }
            _ => "P  Retry password    L  Change limit    Esc  Home",
        };
        frame.render_widget(
            Paragraph::new(help)
                .style(Style::new().fg(Color::DarkGray))
                .alignment(Alignment::Center),
            help_area,
        );
    }

    fn draw_save_path(&self, frame: &mut Frame) {
        let help = if self.overwrite_pending {
            "Ctrl+O  Confirm overwrite    Esc  Cancel"
        } else {
            "Enter  Save    Esc  Cancel"
        };
        self.draw_editor(frame, "Save path", self.editor.as_str(), help, false);
    }

    fn draw_status(&self, frame: &mut Frame, area: Rect) {
        if let Some(status) = &self.status {
            frame.render_widget(
                Paragraph::new(status.as_str())
                    .style(Style::new().fg(Color::Yellow))
                    .alignment(Alignment::Center),
                area,
            );
        }
    }

    fn handle_event(&mut self, terminal_event: Event) {
        match terminal_event {
            Event::Key(key) if key.kind == KeyEventKind::Press => self.handle_key(key),
            Event::Paste(text) => self.handle_paste(&text),
            _ => {}
        }
    }

    fn handle_key(&mut self, key: KeyEvent) {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.exit = true;
            return;
        }

        match self.screen {
            Screen::Splash => match key.code {
                KeyCode::Enter => self.screen = Screen::Home,
                KeyCode::Char('q') | KeyCode::Esc => self.exit = true,
                _ => {}
            },
            Screen::Home => self.handle_home_key(key),
            Screen::ContentSource => self.handle_content_source_key(key),
            Screen::ContentInput => self.handle_content_input_key(key),
            Screen::PasswordSource => self.handle_password_source_key(key),
            Screen::PasswordInput => self.handle_password_input_key(key),
            Screen::Limit => self.handle_limit_key(key),
            Screen::Working => {}
            Screen::Result => self.handle_result_key(key),
            Screen::SavePath => self.handle_save_path_key(key),
        }
    }

    fn handle_home_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => self.move_selection_up(3),
            KeyCode::Down | KeyCode::Char('j') => self.move_selection_down(3),
            KeyCode::Enter => match self.selected {
                0 => self.start_operation(Operation::Protect),
                1 => self.start_operation(Operation::Recover),
                _ => self.exit = true,
            },
            KeyCode::Char('q') | KeyCode::Esc => self.exit = true,
            _ => {}
        }
    }

    fn handle_content_source_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => self.move_selection_up(2),
            KeyCode::Down | KeyCode::Char('j') => self.move_selection_down(2),
            KeyCode::Enter => {
                self.content_source = Some(if self.selected == 0 {
                    InputSource::Typed
                } else {
                    InputSource::File
                });
                self.replace_editor(String::new());
                self.reveal_input = false;
                self.status = None;
                self.screen = Screen::ContentInput;
            }
            KeyCode::Esc => self.reset_to_home(),
            _ => {}
        }
    }

    fn handle_content_input_key(&mut self, key: KeyEvent) {
        if key.code == KeyCode::Esc {
            self.reset_to_home();
            return;
        }

        let source = self.content_source.expect("content source selected");
        if source == InputSource::Typed
            && self.operation == Some(Operation::Protect)
            && key.modifiers.contains(KeyModifiers::CONTROL)
            && key.code == KeyCode::Char('r')
        {
            self.reveal_input = !self.reveal_input;
            return;
        }

        match (source, key.code) {
            (InputSource::Typed, KeyCode::Enter) if key.modifiers.contains(KeyModifiers::SHIFT) => {
                self.editor.push('\n');
                self.status = None;
            }
            (InputSource::Typed, KeyCode::Enter) => self.accept_content(),
            (InputSource::File, KeyCode::Enter) => self.accept_content(),
            (_, KeyCode::Backspace) => {
                self.editor.pop();
                self.status = None;
            }
            (_, KeyCode::Char('u')) if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.replace_editor(String::new());
                self.status = None;
            }
            (_, KeyCode::Char(character))
                if !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                self.editor.push(character);
                self.status = None;
            }
            _ => {}
        }
    }

    fn handle_password_source_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => self.move_selection_up(2),
            KeyCode::Down | KeyCode::Char('j') => self.move_selection_down(2),
            KeyCode::Enter => {
                self.password_source = Some(if self.selected == 0 {
                    InputSource::Typed
                } else {
                    InputSource::File
                });
                self.replace_editor(String::new());
                self.reveal_input = false;
                self.status = None;
                self.screen = Screen::PasswordInput;
            }
            KeyCode::Esc => self.reset_to_home(),
            _ => {}
        }
    }

    fn handle_password_input_key(&mut self, key: KeyEvent) {
        if key.code == KeyCode::Esc {
            self.reset_to_home();
            return;
        }

        let source = self.password_source.expect("password source selected");
        if source == InputSource::Typed
            && key.modifiers.contains(KeyModifiers::CONTROL)
            && key.code == KeyCode::Char('r')
        {
            self.reveal_input = !self.reveal_input;
            return;
        }

        match (source, key.code) {
            (InputSource::Typed, KeyCode::Enter) if key.modifiers.contains(KeyModifiers::SHIFT) => {
                self.editor.push('\n');
                self.status = None;
            }
            (InputSource::Typed, KeyCode::Enter) => self.accept_password(),
            (InputSource::File, KeyCode::Enter) => self.accept_password(),
            (_, KeyCode::Backspace) => {
                self.editor.pop();
                self.status = None;
            }
            (_, KeyCode::Char('u')) if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.replace_editor(String::new());
                self.status = None;
            }
            (_, KeyCode::Char(character))
                if !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                self.editor.push(character);
                self.status = None;
            }
            _ => {}
        }
    }

    fn handle_limit_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Enter => match self.editor.parse::<usize>() {
                Ok(limit) if limit > 0 => {
                    if self.operation == Some(Operation::Protect)
                        && !self.content.is_empty()
                        && self.content.len() > limit
                    {
                        self.status = Some(format!(
                            "The secret is {} bytes. Enter a limit of at least {} bytes.",
                            self.content.len(),
                            self.content.len()
                        ));
                        return;
                    }
                    self.max_secret_size = limit;
                    self.status = None;
                    if !self.password.is_empty() {
                        self.screen = Screen::Working;
                    } else if self.content.is_empty() {
                        self.replace_editor(String::new());
                        self.selected = 0;
                        self.screen = Screen::ContentSource;
                    } else {
                        self.replace_editor(String::new());
                        self.selected = 0;
                        self.screen = Screen::PasswordSource;
                    }
                }
                _ => self.status = Some("Enter a positive byte limit.".to_owned()),
            },
            KeyCode::Backspace => {
                self.editor.pop();
                self.status = None;
            }
            KeyCode::Char(character) if character.is_ascii_digit() => {
                self.editor.push(character);
                self.status = None;
            }
            KeyCode::Esc => self.reset_to_home(),
            _ => {}
        }
    }

    fn handle_result_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('r') if matches!(self.result, Some(ResultContent::Recovered(_))) => {
                self.reveal_result = !self.reveal_result;
            }
            KeyCode::Char('s') if self.result.is_some() => {
                self.replace_editor(String::new());
                self.overwrite_pending = false;
                self.status = None;
                self.screen = Screen::SavePath;
            }
            KeyCode::Char('p') => {
                self.password = Zeroizing::new(Vec::new());
                self.result = None;
                self.selected = 0;
                self.status = None;
                self.screen = Screen::PasswordSource;
            }
            KeyCode::Char('l') if self.operation == Some(Operation::Protect) => {
                self.result = None;
                self.replace_editor(self.max_secret_size.to_string());
                self.status = None;
                self.screen = Screen::Limit;
            }
            KeyCode::Esc => self.reset_to_home(),
            _ => {}
        }
    }

    fn handle_save_path_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Enter if !self.overwrite_pending => self.save_result(false),
            KeyCode::Char('o')
                if self.overwrite_pending && key.modifiers.contains(KeyModifiers::CONTROL) =>
            {
                self.save_result(true);
            }
            KeyCode::Backspace => {
                self.editor.pop();
                self.overwrite_pending = false;
                self.status = None;
            }
            KeyCode::Char(character)
                if !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                self.editor.push(character);
                self.overwrite_pending = false;
                self.status = None;
            }
            KeyCode::Esc => {
                self.replace_editor(String::new());
                self.overwrite_pending = false;
                self.status = None;
                self.screen = Screen::Result;
            }
            _ => {}
        }
    }

    fn handle_paste(&mut self, text: &str) {
        match self.screen {
            Screen::ContentInput | Screen::PasswordInput => {
                self.editor.push_str(text);
                self.status = None;
            }
            Screen::SavePath => {
                self.editor.push_str(text.trim_end_matches(['\r', '\n']));
                self.overwrite_pending = false;
                self.status = None;
            }
            Screen::Limit if text.chars().all(|character| character.is_ascii_digit()) => {
                self.editor.push_str(text);
                self.status = None;
            }
            _ => {}
        }
    }

    fn start_operation(&mut self, operation: Operation) {
        self.operation = Some(operation);
        self.content_source = None;
        self.password_source = None;
        self.content = Zeroizing::new(Vec::new());
        self.password = Zeroizing::new(Vec::new());
        self.result = None;
        self.selected = 0;
        self.status = None;
        if operation == Operation::Protect {
            self.replace_editor(DEFAULT_MAX_SECRET_SIZE.to_string());
            self.screen = Screen::Limit;
        } else {
            self.replace_editor(String::new());
            self.screen = Screen::ContentSource;
        }
    }

    fn accept_content(&mut self) {
        let source = self.content_source.expect("content source selected");
        let content = match source {
            InputSource::Typed => self.editor.as_bytes().to_vec(),
            InputSource::File => match read_file(self.editor.as_str()) {
                Ok(bytes) => bytes,
                Err(error) => {
                    self.status = Some(error);
                    return;
                }
            },
        };
        if content.is_empty() {
            self.status = Some(format!(
                "The {} cannot be empty.",
                self.operation.expect("operation selected").content_name()
            ));
            return;
        }

        let content_size = content.len();
        self.content = Zeroizing::new(content);
        self.selected = 0;
        self.status = None;
        if self.operation == Some(Operation::Protect) {
            if content_size > self.max_secret_size {
                self.replace_editor(self.max_secret_size.to_string());
                self.status = Some(format!(
                    "The secret is {content_size} bytes. Enter a limit of at least {content_size} bytes."
                ));
                self.screen = Screen::Limit;
            } else {
                self.replace_editor(String::new());
                self.screen = Screen::PasswordSource;
            }
        } else {
            self.max_secret_size = content_size;
            self.replace_editor(String::new());
            self.screen = Screen::PasswordSource;
        }
    }

    fn accept_password(&mut self) {
        let source = self.password_source.expect("password source selected");
        let password = match source {
            InputSource::Typed => self.editor.as_bytes().to_vec(),
            InputSource::File => match read_file(self.editor.as_str()) {
                Ok(bytes) => bytes,
                Err(error) => {
                    self.status = Some(error);
                    return;
                }
            },
        };
        if password.is_empty() {
            self.status = Some("The password cannot be empty.".to_owned());
            return;
        }

        self.password = Zeroizing::new(password);
        self.replace_editor(String::new());
        self.status = None;
        self.screen = Screen::Working;
    }

    fn execute_operation(&mut self) {
        let operation = self.operation.expect("operation selected");
        let operation_result = match operation {
            Operation::Protect => protect_with_limit(
                self.content.as_slice(),
                self.password.as_slice(),
                self.max_secret_size,
            )
            .map(ResultContent::Encrypted)
            .map_err(|error| error.to_string()),
            Operation::Recover => std::str::from_utf8(self.content.as_slice())
                .map_err(|_| "Encrypted text must be valid UTF-8.".to_owned())
                .and_then(|encrypted_text| {
                    recover_with_limit(
                        encrypted_text,
                        self.password.as_slice(),
                        self.max_secret_size,
                    )
                    .map(ResultContent::Recovered)
                    .map_err(|error| error.to_string())
                }),
        };

        match operation_result {
            Ok(result) => {
                self.result = Some(result);
                self.status = None;
            }
            Err(error) => {
                self.result = None;
                self.status = Some(error);
            }
        }
        self.reveal_result = false;
        self.screen = Screen::Result;
    }

    fn save_result(&mut self, overwrite: bool) {
        if self.editor.is_empty() {
            self.status = Some("Enter a save path.".to_owned());
            return;
        }

        let path = Path::new(self.editor.as_str());
        if path.exists() && !overwrite {
            self.overwrite_pending = true;
            self.status = Some("That path exists. Press Ctrl+O to overwrite it.".to_owned());
            return;
        }

        let write_result = match &self.result {
            Some(ResultContent::Encrypted(text)) => {
                write_private_file(path, text.as_bytes(), overwrite)
            }
            Some(ResultContent::Recovered(bytes)) => {
                write_private_file(path, bytes.as_slice(), overwrite)
            }
            None => Err(io::Error::other("there is no result to save")),
        };

        match write_result {
            Ok(()) => {
                let path = self.editor.to_string();
                self.replace_editor(String::new());
                self.overwrite_pending = false;
                self.status = Some(format!("Saved to {path}."));
                self.screen = Screen::Result;
            }
            Err(error) => self.status = Some(format!("Could not save the file: {error}")),
        }
    }

    fn reset_to_home(&mut self) {
        self.operation = None;
        self.content_source = None;
        self.password_source = None;
        self.content = Zeroizing::new(Vec::new());
        self.password = Zeroizing::new(Vec::new());
        self.result = None;
        self.replace_editor(String::new());
        self.max_secret_size = DEFAULT_MAX_SECRET_SIZE;
        self.selected = 0;
        self.reveal_input = false;
        self.reveal_result = false;
        self.overwrite_pending = false;
        self.status = None;
        self.screen = Screen::Home;
    }

    fn replace_editor(&mut self, value: String) {
        self.editor = Zeroizing::new(value);
    }

    fn move_selection_up(&mut self, item_count: usize) {
        self.selected = self.selected.checked_sub(1).unwrap_or(item_count - 1);
    }

    fn move_selection_down(&mut self, item_count: usize) {
        self.selected = (self.selected + 1) % item_count;
    }
}

#[derive(Clone, Copy)]
struct CellAspect {
    width: u64,
    height: u64,
}

impl CellAspect {
    const DEFAULT: Self = Self {
        width: 1,
        height: 2,
    };

    fn new(width: u64, height: u64) -> Self {
        let divisor = greatest_common_divisor(width, height);
        Self {
            width: width / divisor,
            height: height / divisor,
        }
    }
}

fn terminal_cell_aspect() -> CellAspect {
    let Ok(window) = terminal::window_size() else {
        return CellAspect::DEFAULT;
    };
    if window.width == 0 || window.height == 0 || window.columns == 0 || window.rows == 0 {
        return CellAspect::DEFAULT;
    }

    CellAspect::new(
        u64::from(window.width) * u64::from(window.rows),
        u64::from(window.height) * u64::from(window.columns),
    )
}

fn greatest_common_divisor(mut left: u64, mut right: u64) -> u64 {
    while right != 0 {
        (left, right) = (right, left % right);
    }
    left.max(1)
}

#[derive(Clone, Copy)]
struct SplashLayout {
    image: Rect,
    tagline: Rect,
    help: Rect,
}

fn splash_layout(
    area: Rect,
    image_dimensions: (u32, u32),
    cell_aspect: CellAspect,
) -> SplashLayout {
    let footer_height = 3;
    let available_width = area.width.saturating_sub(4).min(SPLASH_MAX_WIDTH);
    let available_height = area.height.saturating_sub(footer_height);
    let (pixel_width, pixel_height) = image_dimensions;

    let height_for_width = u64::from(available_width)
        .saturating_mul(cell_aspect.width)
        .saturating_mul(u64::from(pixel_height))
        .div_ceil(
            cell_aspect
                .height
                .saturating_mul(u64::from(pixel_width))
                .max(1),
        );
    let image_height = u16::try_from(height_for_width)
        .unwrap_or(u16::MAX)
        .clamp(1, available_height.max(1));
    let width_for_height = u64::from(image_height)
        .saturating_mul(cell_aspect.height)
        .saturating_mul(u64::from(pixel_width))
        / cell_aspect
            .width
            .saturating_mul(u64::from(pixel_height))
            .max(1);
    let image_width = available_width.min(u16::try_from(width_for_height).unwrap_or(u16::MAX));

    let group_width = image_width
        .max(TAGLINE.chars().count() as u16)
        .min(area.width);
    let group_height = image_height.saturating_add(footer_height).min(area.height);
    let group = centered_area(area, group_width, group_height);
    let [image_row, _, tagline, help] = Layout::vertical([
        Constraint::Length(image_height),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(group);

    SplashLayout {
        image: centered_area(image_row, image_width, image_height),
        tagline,
        help,
    }
}

fn render_braille(frame: &mut Frame, image: &image::RgbaImage, area: Rect) {
    let dot_width = u32::from(area.width).saturating_mul(2);
    let dot_height = u32::from(area.height).saturating_mul(4);
    if dot_width == 0 || dot_height == 0 {
        return;
    }

    let resized = image::imageops::resize(
        image,
        dot_width,
        dot_height,
        image::imageops::FilterType::Lanczos3,
    );
    let mut lines = Vec::with_capacity(usize::from(area.height));

    for cell_y in 0..area.height {
        let mut line = String::with_capacity(usize::from(area.width) * 3);
        for cell_x in 0..area.width {
            let mut dots = 0_u8;
            for dot_y in 0..4_u32 {
                for dot_x in 0..2_u32 {
                    let x = u32::from(cell_x) * 2 + dot_x;
                    let y = u32::from(cell_y) * 4 + dot_y;
                    if braille_dot_is_lit(resized.get_pixel(x, y), x, y) {
                        dots |= BRAILLE_DOT_MASKS[dot_y as usize][dot_x as usize];
                    }
                }
            }
            line.push(char::from_u32(0x2800 + u32::from(dots)).expect("valid Braille character"));
        }
        lines.push(Line::from(line));
    }

    frame.render_widget(
        Paragraph::new(lines).style(Style::new().fg(Color::White)),
        area,
    );
}

fn braille_dot_is_lit(pixel: &image::Rgba<u8>, x: u32, y: u32) -> bool {
    let [red, green, blue, alpha] = pixel.0;
    let luminance =
        (u32::from(red) * 2_126 + u32::from(green) * 7_152 + u32::from(blue) * 722) / 10_000;
    let visible_luminance = luminance * u32::from(alpha) / 255;
    let pattern = u32::from(BAYER_MATRIX[(y % 4) as usize][(x % 4) as usize]);

    visible_luminance > 48 + pattern * 10
}

fn centered_area(area: Rect, maximum_width: u16, height: u16) -> Rect {
    let width = area.width.min(maximum_width);
    let height = area.height.min(height);
    Rect::new(
        area.x + area.width.saturating_sub(width) / 2,
        area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    )
}

fn empty_editor() -> Zeroizing<String> {
    Zeroizing::new(String::with_capacity(DEFAULT_MAX_SECRET_SIZE))
}

fn read_file(path: &str) -> Result<Vec<u8>, String> {
    if path.is_empty() {
        return Err("Enter a file path.".to_owned());
    }
    fs::read(path).map_err(|error| format!("Could not read the file: {error}"))
}

fn write_private_file(path: &Path, content: &[u8], overwrite: bool) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true);
    if overwrite {
        options.create(true).truncate(true);
    } else {
        options.create_new(true);
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options.open(path)?;
    file.write_all(content)?;
    file.flush()?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{Terminal, backend::TestBackend};

    #[test]
    fn splash_continues_to_home() {
        let mut app = test_app();

        app.handle_key(KeyCode::Enter.into());

        assert!(app.screen == Screen::Home);
    }

    #[test]
    fn selected_menu_item_is_blue() {
        let mut app = test_app();
        app.screen = Screen::Home;
        let backend = TestBackend::new(100, 30);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal.draw(|frame| app.draw(frame)).unwrap();

        let selected_item = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .find(|cell| cell.symbol() == "Protect")
            .or_else(|| {
                terminal
                    .backend()
                    .buffer()
                    .content()
                    .iter()
                    .find(|cell| cell.symbol() == "P")
            });
        assert_eq!(selected_item.map(|cell| cell.fg), Some(Color::Blue));
    }

    #[test]
    fn typed_password_is_not_rendered() {
        let mut app = test_app();
        app.screen = Screen::PasswordInput;
        app.password_source = Some(InputSource::Typed);
        app.replace_editor("do not display this password".to_owned());

        let output = render(&mut app);

        assert!(!output.contains("do not display this password"));
        assert!(output.contains("Password hidden"));
    }

    #[test]
    fn typed_password_can_be_revealed() {
        let mut app = test_app();
        app.screen = Screen::PasswordInput;
        app.password_source = Some(InputSource::Typed);
        app.replace_editor("optional password display".to_owned());

        app.handle_key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::CONTROL));

        assert!(render(&mut app).contains("optional password display"));
    }

    #[test]
    fn protection_starts_with_the_secret_limit() {
        let mut app = test_app();

        app.start_operation(Operation::Protect);

        assert!(app.screen == Screen::Limit);
        assert_eq!(app.editor.as_str(), DEFAULT_MAX_SECRET_SIZE.to_string());
    }

    #[test]
    fn initial_protect_limit_advances_to_the_secret() {
        let mut app = test_app();
        app.screen = Screen::Limit;
        app.operation = Some(Operation::Protect);
        app.replace_editor(DEFAULT_MAX_SECRET_SIZE.to_string());

        app.handle_key(KeyCode::Enter.into());

        assert!(app.screen == Screen::ContentSource);
        assert_eq!(app.max_secret_size, DEFAULT_MAX_SECRET_SIZE);
    }

    #[test]
    fn protected_content_advances_to_the_password() {
        let mut app = test_app();
        app.screen = Screen::ContentInput;
        app.operation = Some(Operation::Protect);
        app.content_source = Some(InputSource::Typed);
        app.replace_editor("first line".to_owned());

        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::SHIFT));

        assert_eq!(app.editor.as_str(), "first line\n");
        assert!(app.screen == Screen::ContentInput);

        app.handle_key(KeyCode::Enter.into());

        assert!(app.screen == Screen::PasswordSource);
        assert_eq!(app.content.as_slice(), b"first line\n");
        assert!(app.editor.is_empty());
    }

    #[test]
    fn protect_limit_advances_to_the_password() {
        let mut app = test_app();
        app.screen = Screen::Limit;
        app.operation = Some(Operation::Protect);
        app.content = Zeroizing::new(b"secret".to_vec());
        app.replace_editor(DEFAULT_MAX_SECRET_SIZE.to_string());

        app.handle_key(KeyCode::Enter.into());

        assert!(app.screen == Screen::PasswordSource);
        assert_eq!(app.max_secret_size, DEFAULT_MAX_SECRET_SIZE);
    }

    #[test]
    fn oversized_secret_returns_to_the_limit() {
        let mut app = test_app();
        app.screen = Screen::ContentInput;
        app.operation = Some(Operation::Protect);
        app.content_source = Some(InputSource::Typed);
        app.max_secret_size = 4;
        app.replace_editor("too large".to_owned());

        app.handle_key(KeyCode::Enter.into());

        assert!(app.screen == Screen::Limit);
        assert!(
            app.status
                .as_deref()
                .is_some_and(|status| status.contains("9 bytes"))
        );
    }

    #[test]
    fn recovery_content_skips_the_limit() {
        let mut app = test_app();
        app.screen = Screen::ContentInput;
        app.operation = Some(Operation::Recover);
        app.content_source = Some(InputSource::Typed);
        app.replace_editor("maki:encrypted-text".to_owned());

        app.handle_key(KeyCode::Enter.into());

        assert!(app.screen == Screen::PasswordSource);
        assert_eq!(app.max_secret_size, "maki:encrypted-text".len());
    }

    #[test]
    fn password_enter_advances_and_shift_enter_adds_a_newline() {
        let mut app = test_app();
        app.screen = Screen::PasswordInput;
        app.password_source = Some(InputSource::Typed);
        app.replace_editor("first line".to_owned());

        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::SHIFT));

        assert_eq!(app.editor.as_str(), "first line\n");
        assert!(app.screen == Screen::PasswordInput);

        app.handle_key(KeyCode::Enter.into());

        assert!(app.screen == Screen::Working);
        assert_eq!(app.password.as_slice(), b"first line\n");
    }

    #[test]
    fn recovery_result_has_no_limit_control() {
        let mut app = test_app();
        app.screen = Screen::Result;
        app.operation = Some(Operation::Recover);
        app.status = Some("password is incorrect".to_owned());

        let output = render(&mut app);

        assert!(!output.contains("Change limit"));
    }

    #[test]
    fn recovered_content_requires_reveal() {
        let mut app = test_app();
        app.screen = Screen::Result;
        app.operation = Some(Operation::Recover);
        app.result = Some(ResultContent::Recovered(Zeroizing::new(
            b"hidden recovery words".to_vec(),
        )));

        let hidden = render(&mut app);
        assert!(!hidden.contains("hidden recovery words"));

        app.handle_key(KeyCode::Char('r').into());

        let revealed = render(&mut app);
        assert!(revealed.contains("hidden recovery words"));
    }

    #[test]
    fn splash_group_is_vertically_centered() {
        let layout = splash_layout(Rect::new(0, 0, 100, 30), (1_000, 490), CellAspect::DEFAULT);

        assert_eq!(layout.image.y, 3);
        assert_eq!(layout.help.y, 26);
    }

    #[test]
    fn splash_uses_the_terminal_cell_aspect() {
        let default = splash_layout(Rect::new(0, 0, 100, 40), (1_000, 490), CellAspect::DEFAULT);
        let wider_cells = splash_layout(
            Rect::new(0, 0, 100, 40),
            (1_000, 490),
            CellAspect::new(3, 4),
        );

        assert!(wider_cells.image.height > default.image.height);
    }

    #[test]
    fn splash_renders_braille_characters() {
        let mut image = image::RgbaImage::new(8, 8);
        image.pixels_mut().for_each(|pixel| {
            *pixel = image::Rgba([255, 255, 255, 255]);
        });
        let mut app = App::new(image, (8, 8), CellAspect::DEFAULT);

        let output = render(&mut app);

        assert!(
            output
                .chars()
                .any(|character| ('\u{2801}'..='\u{28ff}').contains(&character))
        );
    }

    fn test_app() -> App {
        let image = image::RgbaImage::new(1, 1);
        App::new(image, (1, 1), CellAspect::DEFAULT)
    }

    fn render(app: &mut App) -> String {
        let backend = TestBackend::new(100, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| app.draw(frame)).unwrap();
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect()
    }
}
