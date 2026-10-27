//! Menu interactivo (TUI) con banner ASCII para el administrador.
//!
//! Flujo: al abrir, la primera entrada es "Iniciar proceso" — con Enter lanza
//! el mantenimiento con la configuracion actual. Debajo hay toggles para elegir
//! el modo simple, que software desinstalar (RustDesk/OpenCode), si aplicar
//! politicas y si aplicar de verdad (por defecto todo es dry-run).
//!
//! Navegacion: flechas o j/k; Enter/Espacio activa o conmuta; q o Esc salen.
//!
//! Las acciones que escriben en consola (iniciar proceso, auditar, estado, gh)
//! restauran primero el terminal y luego ejecutan, para no romper el dibujado.

use crate::process::ProcessConfig;
use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use figlet_rs::FIGfont;
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
    Frame,
};

/// Entradas del menu. Unas son acciones, otras conmutan un flag de config.
#[derive(Clone, Copy)]
enum Entry {
    Start,
    ToggleSimple,
    ToggleRustdesk,
    ToggleOpencode,
    TogglePolicies,
    ToggleApply,
    Audit,
    PolicyStatus,
    GhWhoami,
    Quit,
}

const ENTRIES: &[Entry] = &[
    Entry::Start,
    Entry::ToggleSimple,
    Entry::ToggleRustdesk,
    Entry::ToggleOpencode,
    Entry::TogglePolicies,
    Entry::ToggleApply,
    Entry::Audit,
    Entry::PolicyStatus,
    Entry::GhWhoami,
    Entry::Quit,
];

/// Lo que el menu decide hacer al salir del bucle, para ejecutarlo ya con el
/// terminal restaurado.
enum Outcome {
    Quit,
    Process(ProcessConfig),
    AuditList,
    PolicyStatus,
    GhWhoami,
}

struct App {
    state: ListState,
    banner: String,
    status: String,
    // Configuracion acumulada por los toggles.
    cfg: ProcessConfig,
}

impl App {
    fn new() -> Self {
        let mut state = ListState::default();
        state.select(Some(0));
        Self {
            state,
            banner: build_banner("AEGN"),
            status: "Configura con Espacio, luego 'Iniciar proceso' con Enter.".to_string(),
            cfg: ProcessConfig::default(),
        }
    }

    fn next(&mut self) {
        let i = self.state.selected().unwrap_or(0);
        let next = if i >= ENTRIES.len() - 1 { 0 } else { i + 1 };
        self.state.select(Some(next));
    }

    fn prev(&mut self) {
        let i = self.state.selected().unwrap_or(0);
        let prev = if i == 0 { ENTRIES.len() - 1 } else { i - 1 };
        self.state.select(Some(prev));
    }

    /// Etiqueta mostrada para una entrada, con marca [x]/[ ] en los toggles.
    fn label(&self, entry: Entry) -> String {
        let chk = |on: bool| if on { "[x]" } else { "[ ]" };
        match entry {
            Entry::Start => "  Iniciar proceso".to_string(),
            Entry::ToggleSimple => format!("{} Modo simple (sin inventario)", chk(self.cfg.simple)),
            Entry::ToggleRustdesk => {
                format!("{} Desinstalar RustDesk", chk(self.cfg.uninstall_rustdesk))
            }
            Entry::ToggleOpencode => {
                format!("{} Desinstalar OpenCode", chk(self.cfg.uninstall_opencode))
            }
            Entry::TogglePolicies => {
                format!("{} Aplicar politicas de ejecucion", chk(self.cfg.apply_policies))
            }
            Entry::ToggleApply => format!("{} APLICAR DE VERDAD (si no, dry-run)", chk(self.cfg.apply)),
            Entry::Audit => "  Auditar: solo listar software".to_string(),
            Entry::PolicyStatus => "  Ver estado de politicas".to_string(),
            Entry::GhWhoami => "  GitHub: verificar token".to_string(),
            Entry::Quit => "  Salir".to_string(),
        }
    }

    /// Texto de ayuda del panel derecho para la entrada seleccionada.
    fn help(&self, entry: Entry) -> &'static str {
        match entry {
            Entry::Start => "Ejecuta el proceso con la configuracion de los toggles.",
            Entry::ToggleSimple => "Omite el inventario previo y reduce la salida.",
            Entry::ToggleRustdesk => "Incluye RustDesk (herramienta de acceso remoto) en la desinstalacion.",
            Entry::ToggleOpencode => "Incluye OpenCode en la desinstalacion.",
            Entry::TogglePolicies => "Bloquea .exe en AppData\\Local y Downloads (AppLocker).",
            Entry::ToggleApply => "Si esta activo se aplican cambios reales (requiere admin). Si no, solo simula.",
            Entry::Audit => "Lista el software instalado sin cambiar nada.",
            Entry::PolicyStatus => "Muestra el estado actual de AppLocker y AppIDSvc.",
            Entry::GhWhoami => "Verifica GITHUB_TOKEN e identifica al usuario.",
            Entry::Quit => "Cierra el agente.",
        }
    }
}

/// Genera el banner ASCII con la fuente estandar de FIGlet.
fn build_banner(text: &str) -> String {
    match FIGfont::standard() {
        Ok(font) => font
            .convert(text)
            .map(|f| f.to_string())
            .unwrap_or_else(|| text.to_string()),
        Err(_) => text.to_string(),
    }
}

/// Punto de entrada del menu interactivo.
pub fn run() -> Result<()> {
    let mut terminal = ratatui::init();
    let mut app = App::new();

    let outcome = loop {
        terminal.draw(|f| draw(f, &mut app))?;

        if let Event::Key(key) = event::read()? {
            if key.kind != KeyEventKind::Press {
                continue;
            }
            let entry = ENTRIES[app.state.selected().unwrap_or(0)];
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => break Outcome::Quit,
                KeyCode::Down | KeyCode::Char('j') => app.next(),
                KeyCode::Up | KeyCode::Char('k') => app.prev(),
                KeyCode::Char(' ') => toggle(&mut app, entry),
                KeyCode::Enter => match entry {
                    Entry::Start => {
                        break Outcome::Process(ProcessConfig {
                            simple: app.cfg.simple,
                            uninstall_rustdesk: app.cfg.uninstall_rustdesk,
                            uninstall_opencode: app.cfg.uninstall_opencode,
                            apply_policies: app.cfg.apply_policies,
                            apply: app.cfg.apply,
                        })
                    }
                    Entry::Audit => break Outcome::AuditList,
                    Entry::PolicyStatus => break Outcome::PolicyStatus,
                    Entry::GhWhoami => break Outcome::GhWhoami,
                    Entry::Quit => break Outcome::Quit,
                    // Sobre un toggle, Enter conmuta igual que Espacio.
                    _ => toggle(&mut app, entry),
                },
                _ => {}
            }
        }
    };

    ratatui::restore();

    // Ya con el terminal normal, ejecuta lo elegido e imprime en consola.
    match outcome {
        Outcome::Quit => Ok(()),
        Outcome::Process(cfg) => crate::process::run(&cfg),
        Outcome::AuditList => crate::audit::list(),
        Outcome::PolicyStatus => crate::policy::status(),
        Outcome::GhWhoami => crate::github::whoami(),
    }
}

/// Conmuta el flag asociado a un toggle; en acciones no hace nada.
fn toggle(app: &mut App, entry: Entry) {
    match entry {
        Entry::ToggleSimple => app.cfg.simple = !app.cfg.simple,
        Entry::ToggleRustdesk => app.cfg.uninstall_rustdesk = !app.cfg.uninstall_rustdesk,
        Entry::ToggleOpencode => app.cfg.uninstall_opencode = !app.cfg.uninstall_opencode,
        Entry::TogglePolicies => app.cfg.apply_policies = !app.cfg.apply_policies,
        Entry::ToggleApply => app.cfg.apply = !app.cfg.apply,
        _ => {}
    }
}

fn draw(f: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(8), // banner
            Constraint::Min(8),    // menu + descripcion
            Constraint::Length(3), // barra de estado
        ])
        .split(f.area());

    let banner = Paragraph::new(app.banner.clone())
        .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL).title(" Escola AEGN "));
    f.render_widget(banner, chunks[0]);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(chunks[1]);

    let items: Vec<ListItem> = ENTRIES
        .iter()
        .map(|e| ListItem::new(Line::from(Span::raw(app.label(*e)))))
        .collect();

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(" Menu "))
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");
    f.render_stateful_widget(list, body[0], &mut app.state);

    let selected = ENTRIES[app.state.selected().unwrap_or(0)];
    let description = Paragraph::new(app.help(selected))
        .wrap(Wrap { trim: true })
        .block(Block::default().borders(Borders::ALL).title(" Descripcion "));
    f.render_widget(description, body[1]);

    let mode = if app.cfg.apply {
        Span::styled("MODO REAL", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))
    } else {
        Span::styled("DRY-RUN", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))
    };
    let status = Paragraph::new(Line::from(vec![
        Span::raw(format!("{}  |  ", app.status)),
        mode,
    ]))
    .style(Style::default().fg(Color::Yellow))
    .block(Block::default().borders(Borders::ALL).title(" Estado "));
    f.render_widget(status, chunks[2]);
}
