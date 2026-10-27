//! Menu interactivo (TUI) con banner ASCII para el administrador.
//!
//! Pantalla: banner arriba, menu a la izquierda agrupado en secciones (Proceso,
//! Opciones, Herramientas) y a la derecha un panel que muestra el plan de lo que
//! se va a hacer o, tras lanzar una accion, su salida en vivo con scroll.
//!
//! Las acciones se ejecutan como un subproceso del propio binario con el
//! subcomando de CLI equivalente (`aegn run ...`, `aegn audit list`...), asi la
//! salida se captura linea a linea sin tocar los modulos y el menu sigue abierto.
//!
//! Teclas: flechas o j/k mueven; Espacio conmuta; Enter ejecuta; a alterna el
//! modo real; PgUp/PgDn/Inicio/Fin y flechas laterales desplazan la salida;
//! c la limpia; q o Esc salen. En modo real se pide confirmacion antes de
//! ejecutar.

use crate::process::ProcessConfig;
use anyhow::{Context, Result};
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use figlet_rs::FIGfont;
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{
        Block, BorderType, Borders, Clear, List, ListItem, ListState, Padding, Paragraph, Wrap,
    },
    Frame,
};
use std::io::{BufRead, BufReader, Read};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

/// Entradas del menu. Las cabeceras separan secciones y no son seleccionables.
#[derive(Clone, Copy, PartialEq)]
enum Entry {
    Header(&'static str),
    Start,
    ToggleSimple,
    ToggleRustdesk,
    ToggleOpencode,
    TogglePolicies,
    ToggleAuditOnly,
    ToggleFirewall,
    ToggleApply,
    Audit,
    Admins,
    Status,
    Events,
    ScheduleInstall,
    RevertAll,
    GhWhoami,
    Quit,
}

impl Entry {
    /// Acciones que cambian el equipo con --apply y piden confirmacion.
    fn destructive(self) -> bool {
        matches!(
            self,
            Entry::Start | Entry::ScheduleInstall | Entry::RevertAll
        )
    }
}

const ENTRIES: &[Entry] = &[
    Entry::Header("PROCESO"),
    Entry::Start,
    Entry::Header("OPCIONES"),
    Entry::ToggleSimple,
    Entry::ToggleRustdesk,
    Entry::ToggleOpencode,
    Entry::TogglePolicies,
    Entry::ToggleAuditOnly,
    Entry::ToggleFirewall,
    Entry::ToggleApply,
    Entry::Header("HERRAMIENTAS"),
    Entry::Audit,
    Entry::Admins,
    Entry::Status,
    Entry::Events,
    Entry::ScheduleInstall,
    Entry::RevertAll,
    Entry::GhWhoami,
    Entry::Quit,
];

const SPINNER: &[char] = &['|', '/', '-', '\\'];

/// Mensajes del hilo lector del subproceso.
enum Msg {
    Line(String),
    /// Ambos flujos cerrados: el proceso ha terminado o esta terminando.
    Done,
}

/// Ejecucion en curso o terminada de una accion.
struct Job {
    title: String,
    lines: Vec<String>,
    /// None mientras corre; Some(codigo) al terminar (codigo None si lo mato
    /// una senal o no se pudo esperar).
    exit: Option<Option<i32>>,
    rx: Option<Receiver<Msg>>,
    child: Option<Child>,
    /// Primera linea visible; si `follow`, se pega al final.
    scroll: usize,
    follow: bool,
    /// Desplazamiento horizontal para lineas largas (XML, tablas).
    hscroll: u16,
}

struct App {
    state: ListState,
    banner: String,
    cfg: ProcessConfig,
    job: Option<Job>,
    /// Accion pendiente de confirmar (modo real).
    confirm: Option<Entry>,
    tick: usize,
    notice: Option<String>,
}

impl App {
    fn new() -> Self {
        let mut state = ListState::default();
        state.select(Some(first_selectable()));
        Self {
            state,
            banner: build_banner("AEGN"),
            cfg: ProcessConfig::default(),
            job: None,
            confirm: None,
            tick: 0,
            notice: None,
        }
    }

    fn selected(&self) -> Entry {
        ENTRIES[self.state.selected().unwrap_or(0)]
    }

    /// Mueve la seleccion saltando cabeceras, con vuelta al principio/final.
    fn step(&mut self, forward: bool) {
        let n = ENTRIES.len();
        let mut i = self.state.selected().unwrap_or(0);
        loop {
            i = if forward {
                (i + 1) % n
            } else {
                (i + n - 1) % n
            };
            if !matches!(ENTRIES[i], Entry::Header(_)) {
                break;
            }
        }
        self.state.select(Some(i));
    }

    fn running(&self) -> bool {
        self.job.as_ref().is_some_and(|j| j.exit.is_none())
    }

    fn label(&self, entry: Entry) -> String {
        let chk = |on: bool| if on { "[x]" } else { "[ ]" };
        match entry {
            Entry::Header(h) => h.to_string(),
            Entry::Start => "Iniciar proceso".to_string(),
            Entry::ToggleSimple => format!("{} Modo simple (sin inventario)", chk(self.cfg.simple)),
            Entry::ToggleRustdesk => {
                format!("{} Desinstalar RustDesk", chk(self.cfg.uninstall_rustdesk))
            }
            Entry::ToggleOpencode => {
                format!("{} Desinstalar OpenCode", chk(self.cfg.uninstall_opencode))
            }
            Entry::TogglePolicies => {
                format!("{} Politicas de ejecucion", chk(self.cfg.apply_policies))
            }
            Entry::ToggleAuditOnly => {
                format!("  {} solo auditar (no bloquea)", chk(self.cfg.audit_only))
            }
            Entry::ToggleFirewall => {
                format!("{} Firewall: acceso remoto", chk(self.cfg.firewall))
            }
            Entry::ToggleApply => format!("{} APLICAR DE VERDAD", chk(self.cfg.apply)),
            Entry::Audit => "Auditar software instalado".to_string(),
            Entry::Admins => "Administradores locales".to_string(),
            Entry::Status => "Estado de protecciones".to_string(),
            Entry::Events => "Eventos AppLocker".to_string(),
            Entry::ScheduleInstall => "Instalar tarea diaria".to_string(),
            Entry::RevertAll => "Revertir todo lo de AEGN".to_string(),
            Entry::GhWhoami => "GitHub: verificar token".to_string(),
            Entry::Quit => "Salir".to_string(),
        }
    }

    fn help(&self, entry: Entry) -> &'static str {
        match entry {
            Entry::Header(_) => "",
            Entry::Start => "Ejecuta el proceso con las opciones marcadas.",
            Entry::ToggleSimple => "Omite el inventario previo y reduce la salida.",
            Entry::ToggleRustdesk => "Incluye RustDesk (acceso remoto) en la desinstalacion.",
            Entry::ToggleOpencode => "Incluye OpenCode en la desinstalacion.",
            Entry::TogglePolicies => "AppLocker: solo se ejecutan programas, scripts y MSI de Windows y Program Files (los admins, todo). AppData\\Local y Downloads, denegados.",
            Entry::ToggleAuditOnly => "AppLocker en modo auditoria: no bloquea, solo registra lo que bloquearia. Usalo primero en cada aula y revisa 'Eventos AppLocker'.",
            Entry::ToggleFirewall => "Bloquea la salida por los puertos de RustDesk, AnyDesk y TeamViewer.",
            Entry::ToggleApply => "Activo: cambios reales (requiere admin). Inactivo: solo simula.",
            Entry::Audit => "Lista el software instalado sin cambiar nada.",
            Entry::Admins => "Miembros del grupo Administradores. Ningun alumno debe estar.",
            Entry::Status => "AppLocker y AppIDSvc, reglas de firewall y tarea programada.",
            Entry::Events => "Ultimos bloqueos (y avisos de auditoria) registrados por AppLocker.",
            Entry::ScheduleInstall => "Tarea SYSTEM que reaplica el proceso al arrancar y a diario. Requiere aegn.exe en Program Files.",
            Entry::RevertAll => "Retira las reglas AppLocker y de firewall AEGN y la tarea programada.",
            Entry::GhWhoami => "Verifica GITHUB_TOKEN e identifica al usuario.",
            Entry::Quit => "Cierra el agente.",
        }
    }

    /// Pasos que ejecutaria "Iniciar proceso" con la configuracion actual.
    fn plan(&self) -> Vec<&'static str> {
        let c = &self.cfg;
        [
            (!c.simple, "Inventario de software"),
            (!c.simple, "Administradores locales"),
            (c.uninstall_rustdesk, "Desinstalar RustDesk"),
            (c.uninstall_opencode, "Desinstalar OpenCode"),
            (
                c.apply_policies && !c.audit_only,
                "AppLocker: bloquear carpetas de usuario",
            ),
            (
                c.apply_policies && c.audit_only,
                "AppLocker en modo auditoria",
            ),
            (c.firewall, "Firewall: puertos de acceso remoto"),
        ]
        .into_iter()
        .filter_map(|(on, step)| on.then_some(step))
        .collect()
    }

    /// Argumentos de CLI equivalentes a una accion del menu.
    fn args(&self, entry: Entry) -> Option<Vec<&'static str>> {
        let c = &self.cfg;
        let mut args = match entry {
            Entry::Start => {
                let mut a = vec!["run"];
                for (on, flag) in [
                    (c.simple, "--simple"),
                    (!c.uninstall_rustdesk, "--no-rustdesk"),
                    (!c.uninstall_opencode, "--no-opencode"),
                    (!c.apply_policies, "--no-policies"),
                    (c.apply_policies && c.audit_only, "--audit-only"),
                    (!c.firewall, "--no-firewall"),
                ] {
                    if on {
                        a.push(flag);
                    }
                }
                a
            }
            Entry::Audit => vec!["audit", "list"],
            Entry::Admins => vec!["audit", "admins"],
            Entry::Status => vec!["status"],
            Entry::Events => vec!["policy", "events"],
            Entry::ScheduleInstall if c.audit_only => vec!["schedule", "install", "--audit-only"],
            Entry::ScheduleInstall => vec!["schedule", "install"],
            Entry::RevertAll => vec!["revert"],
            Entry::GhWhoami => vec!["gh", "whoami"],
            _ => return None,
        };
        if c.apply && entry.destructive() {
            args.push("--apply");
        }
        Some(args)
    }

    /// Enter sobre una entrada: conmuta, pide confirmacion o lanza la accion.
    fn activate(&mut self, entry: Entry) -> Result<()> {
        if self.toggle(entry) {
            return Ok(());
        }
        if self.running() {
            self.notice = Some("Espera a que termine la accion en curso.".into());
            return Ok(());
        }
        if entry == Entry::Start && self.plan().is_empty() {
            self.notice = Some("No hay ningun paso marcado en Opciones.".into());
            return Ok(());
        }
        if self.cfg.apply && entry.destructive() {
            self.confirm = Some(entry);
            return Ok(());
        }
        self.launch(entry)
    }

    fn launch(&mut self, entry: Entry) -> Result<()> {
        let Some(args) = self.args(entry) else {
            return Ok(());
        };
        let title = match entry {
            _ if args.contains(&"--apply") => format!("{} [REAL]", self.label(entry)),
            e if e.destructive() => format!("{} [dry-run]", self.label(entry)),
            _ => self.label(entry),
        };
        self.notice = None;
        self.job = Some(spawn(title, &args)?);
        Ok(())
    }

    /// Conmuta el flag de un toggle. Devuelve false si la entrada no es toggle.
    fn toggle(&mut self, entry: Entry) -> bool {
        let c = &mut self.cfg;
        let flag = match entry {
            Entry::ToggleSimple => &mut c.simple,
            Entry::ToggleRustdesk => &mut c.uninstall_rustdesk,
            Entry::ToggleOpencode => &mut c.uninstall_opencode,
            Entry::TogglePolicies => &mut c.apply_policies,
            Entry::ToggleAuditOnly => &mut c.audit_only,
            Entry::ToggleFirewall => &mut c.firewall,
            Entry::ToggleApply => &mut c.apply,
            _ => return false,
        };
        *flag = !*flag;
        true
    }

    /// Recoge la salida pendiente del subproceso.
    fn pump(&mut self) {
        let Some(job) = self.job.as_mut() else { return };
        let Some(rx) = job.rx.as_ref() else { return };
        while let Ok(msg) = rx.try_recv() {
            match msg {
                Msg::Line(l) => job.lines.push(l),
                Msg::Done => {
                    let code = job
                        .child
                        .take()
                        .and_then(|mut c| c.wait().ok())
                        .and_then(|s| s.code());
                    job.exit = Some(code);
                    job.rx = None;
                    break;
                }
            }
        }
    }

    fn scroll(&mut self, delta: isize) {
        if let Some(job) = self.job.as_mut() {
            job.follow = false;
            job.scroll = job
                .scroll
                .saturating_add_signed(delta)
                .min(job.lines.len().saturating_sub(1));
        }
    }
}

/// Lanza `aegn <args>` y lee stdout y stderr en hilos que envian cada linea.
fn spawn(title: String, args: &[&str]) -> Result<Job> {
    let exe = std::env::current_exe().context("no se pudo localizar el ejecutable")?;
    let mut child = Command::new(exe)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("no se pudo lanzar el subproceso")?;

    let (tx, rx) = mpsc::channel();
    let readers: Vec<Box<dyn Read + Send>> = vec![
        Box::new(child.stdout.take().expect("stdout piped")),
        Box::new(child.stderr.take().expect("stderr piped")),
    ];
    let handles: Vec<_> = readers
        .into_iter()
        .map(|r| {
            let tx = tx.clone();
            std::thread::spawn(move || {
                for line in BufReader::new(r).split(b'\n').map_while(|l| l.ok()) {
                    let _ = tx.send(Msg::Line(clean(&String::from_utf8_lossy(&line))));
                }
            })
        })
        .collect();

    // Cuando ambos flujos se cierran se avisa; el wait() con el codigo de
    // salida lo hace pump(), que es quien guarda el Child.
    std::thread::spawn(move || {
        for h in handles {
            let _ = h.join();
        }
        let _ = tx.send(Msg::Done);
    });

    Ok(Job {
        title,
        lines: Vec::new(),
        exit: None,
        rx: Some(rx),
        child: Some(child),
        scroll: 0,
        hscroll: 0,
        follow: true,
    })
}

/// Deja una linea imprimible: se queda con lo ultimo tras un '\r' (barras de
/// progreso de winget), quita secuencias ANSI y expande tabuladores.
fn clean(raw: &str) -> String {
    let last = raw.trim_end_matches('\r').rsplit('\r').next().unwrap_or("");
    let mut out = String::with_capacity(last.len());
    let mut chars = last.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\x1b' => {
                if chars.peek() == Some(&'[') {
                    chars.next();
                    for c in chars.by_ref() {
                        if c.is_ascii_alphabetic() {
                            break;
                        }
                    }
                }
            }
            '\t' => out.push_str("    "),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

fn first_selectable() -> usize {
    ENTRIES
        .iter()
        .position(|e| !matches!(e, Entry::Header(_)))
        .unwrap_or(0)
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
    let result = event_loop(&mut terminal);
    ratatui::restore();
    result
}

fn event_loop(terminal: &mut ratatui::DefaultTerminal) -> Result<()> {
    let mut app = App::new();
    loop {
        app.pump();
        terminal.draw(|f| draw(f, &mut app))?;

        if !event::poll(Duration::from_millis(120))? {
            app.tick = app.tick.wrapping_add(1);
            continue;
        }
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }

        if let Some(entry) = app.confirm {
            app.confirm = None;
            if matches!(key.code, KeyCode::Char('s') | KeyCode::Char('S')) {
                app.launch(entry)?;
            } else {
                app.notice = Some("Cancelado.".into());
            }
            continue;
        }

        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => {
                if app.running() {
                    app.notice = Some("Hay una accion en curso; espera a que termine.".into());
                } else {
                    return Ok(());
                }
            }
            KeyCode::Down | KeyCode::Char('j') => app.step(true),
            KeyCode::Up | KeyCode::Char('k') => app.step(false),
            KeyCode::Char(' ') => {
                app.toggle(app.selected());
            }
            KeyCode::Char('a') => {
                app.toggle(Entry::ToggleApply);
            }
            KeyCode::Enter => match app.selected() {
                Entry::Quit if !app.running() => return Ok(()),
                entry => app.activate(entry)?,
            },
            KeyCode::PageDown => app.scroll(10),
            KeyCode::PageUp => app.scroll(-10),
            KeyCode::Home => app.scroll(isize::MIN / 2),
            KeyCode::Right | KeyCode::Char('l') => {
                if let Some(job) = app.job.as_mut() {
                    job.hscroll = job.hscroll.saturating_add(8);
                }
            }
            KeyCode::Left | KeyCode::Char('h') => {
                if let Some(job) = app.job.as_mut() {
                    job.hscroll = job.hscroll.saturating_sub(8);
                }
            }
            KeyCode::End => {
                if let Some(job) = app.job.as_mut() {
                    job.follow = true;
                }
            }
            KeyCode::Char('c') if !app.running() => app.job = None,
            _ => {}
        }
    }
}

fn draw(f: &mut Frame, app: &mut App) {
    let accent = if app.cfg.apply {
        Color::Red
    } else {
        Color::Cyan
    };
    let rounded = |title: Line<'static>| {
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(accent))
            .title(title)
    };

    let banner_h = app.banner.lines().count() as u16 + 2;
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(banner_h),
            Constraint::Min(8),
            Constraint::Length(1),
        ])
        .split(f.area());

    // Banner con la insignia de modo en el titulo derecho.
    let badge = if app.cfg.apply {
        Span::styled(
            " MODO REAL ",
            Style::default()
                .fg(Color::White)
                .bg(Color::Red)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(
            " DRY-RUN ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )
    };
    let banner = Paragraph::new(app.banner.clone())
        .style(Style::default().fg(accent).add_modifier(Modifier::BOLD))
        .alignment(Alignment::Center)
        .block(
            rounded(Line::from(" Escola AEGN · agente de endpoints "))
                .title(Line::from(vec![badge, Span::raw(" ")]).right_aligned())
                .title_bottom(
                    Line::from(format!(" v{} ", env!("CARGO_PKG_VERSION"))).right_aligned(),
                ),
        );
    f.render_widget(banner, rows[0]);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(40), Constraint::Min(30)])
        .split(rows[1]);

    draw_menu(f, app, body[0], rounded(Line::from(" Menu ")));
    if app.job.is_some() {
        draw_output(f, app, body[1], accent);
    } else {
        draw_detail(f, app, body[1], rounded(Line::from(" Detalle ")));
    }

    // Barra inferior: aviso puntual o atajos.
    let footer = match &app.notice {
        Some(n) => Line::from(Span::styled(
            format!(" {n}"),
            Style::default().fg(Color::Yellow),
        )),
        None => {
            let key = |k: &'static str| {
                Span::styled(k, Style::default().fg(accent).add_modifier(Modifier::BOLD))
            };
            let txt = |t: &'static str| Span::styled(t, Style::default().fg(Color::DarkGray));
            Line::from(vec![
                txt(" "),
                key("↑↓"),
                txt(" mover  "),
                key("Espacio"),
                txt(" marcar  "),
                key("Enter"),
                txt(" ejecutar  "),
                key("a"),
                txt(" modo real  "),
                key("PgUp/PgDn ←→"),
                txt(" salida  "),
                key("c"),
                txt(" limpiar  "),
                key("q"),
                txt(" salir"),
            ])
        }
    };
    f.render_widget(Paragraph::new(footer), rows[2]);

    if let Some(entry) = app.confirm {
        draw_confirm(f, app, entry);
    }
}

fn draw_menu(f: &mut Frame, app: &mut App, area: Rect, block: Block<'static>) {
    let items: Vec<ListItem> = ENTRIES
        .iter()
        .map(|e| match e {
            Entry::Header(_) => ListItem::new(Line::from(Span::styled(
                app.label(*e),
                Style::default()
                    .fg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            ))),
            Entry::ToggleApply if app.cfg.apply => ListItem::new(Line::from(Span::styled(
                format!("  {}", app.label(*e)),
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ))),
            Entry::Start => ListItem::new(Line::from(Span::styled(
                format!("  {}", app.label(*e)),
                Style::default().add_modifier(Modifier::BOLD),
            ))),
            _ => ListItem::new(Line::from(format!("  {}", app.label(*e)))),
        })
        .collect();

    let highlight = if app.cfg.apply {
        Color::Red
    } else {
        Color::Cyan
    };
    let list = List::new(items)
        .block(block)
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(highlight)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");
    f.render_stateful_widget(list, area, &mut app.state);
}

fn draw_detail(f: &mut Frame, app: &App, area: Rect, block: Block<'static>) {
    let entry = app.selected();
    let dim = Style::default().fg(Color::DarkGray);
    let mut lines = vec![
        Line::from(Span::styled(
            app.label(entry),
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(app.help(entry)),
        Line::from(""),
    ];

    let shows_plan = matches!(
        entry,
        Entry::Start
            | Entry::ToggleSimple
            | Entry::ToggleRustdesk
            | Entry::ToggleOpencode
            | Entry::TogglePolicies
            | Entry::ToggleAuditOnly
            | Entry::ToggleFirewall
            | Entry::ToggleApply
    );
    if shows_plan {
        lines.push(Line::from(Span::styled(
            "Plan de ejecucion",
            dim.add_modifier(Modifier::BOLD),
        )));
        let plan = app.plan();
        if plan.is_empty() {
            lines.push(Line::from(Span::styled(
                "  (ningun paso marcado)",
                Style::default().fg(Color::Yellow),
            )));
        }
        for (i, step) in plan.iter().enumerate() {
            lines.push(Line::from(format!("  {}. {step}", i + 1)));
        }
        lines.push(Line::from(""));
    }

    if let Some(args) = app.args(entry) {
        lines.push(Line::from(Span::styled(
            "Equivale a",
            dim.add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(Span::styled(
            format!("  aegn {}", args.join(" ")),
            Style::default().fg(Color::Green),
        )));
    }

    let p = Paragraph::new(Text::from(lines))
        .wrap(Wrap { trim: false })
        .block(block.padding(Padding::horizontal(1)));
    f.render_widget(p, area);
}

fn draw_output(f: &mut Frame, app: &mut App, area: Rect, accent: Color) {
    let tick = app.tick;
    let Some(job) = app.job.as_mut() else { return };

    let (state, color) = match job.exit {
        None => (
            format!(" {} ejecutando ", SPINNER[tick % SPINNER.len()]),
            Color::Yellow,
        ),
        Some(Some(0)) => (" ok terminado ".to_string(), Color::Green),
        Some(Some(code)) => (format!(" x error (codigo {code}) "), Color::Red),
        Some(None) => (" x interrumpido ".to_string(), Color::Red),
    };

    let inner_h = area.height.saturating_sub(2) as usize;
    let max_scroll = job.lines.len().saturating_sub(inner_h);
    if job.follow || job.scroll > max_scroll {
        job.scroll = max_scroll;
    }
    let pos = if job.lines.is_empty() {
        String::new()
    } else {
        format!(
            " {}-{}/{} ",
            job.scroll + 1,
            (job.scroll + inner_h).min(job.lines.len()),
            job.lines.len()
        )
    };

    let text: Vec<Line> = job
        .lines
        .iter()
        .skip(job.scroll)
        .take(inner_h)
        .map(|l| Line::from(Span::styled(l.clone(), line_style(l))))
        .collect();

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(accent))
        .title(Line::from(format!(" Salida · {} ", job.title)))
        .title(
            Line::from(Span::styled(
                state,
                Style::default().fg(color).add_modifier(Modifier::BOLD),
            ))
            .right_aligned(),
        )
        .title_bottom(
            Line::from(Span::styled(pos, Style::default().fg(Color::DarkGray))).right_aligned(),
        );
    let hscroll = job.hscroll;
    f.render_widget(Paragraph::new(text).scroll((0, hscroll)).block(block), area);
}

/// Color por tipo de linea segun las etiquetas que imprimen los modulos.
fn line_style(line: &str) -> Style {
    let l = line.trim_start();
    let fg = if l.starts_with("[ok]") || l.starts_with("Politica AEGN aplicada") {
        Color::Green
    } else if l.starts_with("[aviso]") || l.starts_with("[dry-run]") || l.starts_with("NOT_FOUND") {
        Color::Yellow
    } else if l.starts_with("Error") || l.starts_with("[stderr]") || l.starts_with("[error]") {
        Color::Red
    } else if l.starts_with("--") || l.starts_with("====") {
        Color::Cyan
    } else if l.starts_with("[info]") || l.starts_with("[nota]") {
        Color::DarkGray
    } else {
        return Style::default();
    };
    Style::default().fg(fg)
}

fn draw_confirm(f: &mut Frame, app: &App, entry: Entry) {
    let area = f.area();
    let w = 56.min(area.width);
    let h = 8.min(area.height);
    let rect = Rect::new(
        area.x + (area.width - w) / 2,
        area.y + (area.height - h) / 2,
        w,
        h,
    );

    let text = vec![
        Line::from(Span::styled(
            app.label(entry),
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from("Se aplicaran cambios REALES en este equipo."),
        Line::from("Requiere consola de administrador."),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                " s ",
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Red)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" continuar    "),
            Span::styled(
                " otra tecla ",
                Style::default().fg(Color::Black).bg(Color::Gray),
            ),
            Span::raw(" cancelar"),
        ]),
    ];
    let p = Paragraph::new(text).alignment(Alignment::Center).block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Double)
            .border_style(Style::default().fg(Color::Red))
            .title(Line::from(" Confirmar ").centered()),
    );
    f.render_widget(Clear, rect);
    f.render_widget(p, rect);
}
