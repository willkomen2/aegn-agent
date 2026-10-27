//! Menu interactivo (TUI) con banner ASCII para el administrador.
//!
//! Pantalla: banner arriba, menu a la izquierda agrupado en secciones (Proceso,
//! Opciones, Herramientas) y a la derecha un panel que muestra el plan de lo que
//! se va a hacer o, tras lanzar una accion, su salida en vivo con scroll.
//!
//! Las acciones se ejecutan como un subproceso del propio binario con el
//! subcomando de CLI equivalente (`aegn executar ...`, `aegn auditoria listar`...), asi la
//! salida se captura linea a linea sin tocar los modulos y el menu sigue abierto.
//!
//! Teclas: flechas o j/k mueven; Espacio conmuta; Enter ejecuta; a alterna el
//! modo real; PgUp/PgDn/Inicio/Fin y flechas laterales desplazan la salida;
//! c la limpia; q o Esc salen. En modo real se pide la contraseña del agente
//! antes de ejecutar; se verifica aqui y se pasa al subproceso por AEGN_SENHA.
//!
//! Los textos de pantalla estan en portugues.

use crate::auth;
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
    ToggleClean,
    TogglePolicies,
    ToggleAuditOnly,
    ToggleFirewall,
    ToggleBrowser,
    ToggleApply,
    Audit,
    Suspects,
    Clean,
    Evidence,
    History,
    Admins,
    Status,
    Events,
    ScheduleInstall,
    Update,
    RevertAll,
    Quit,
}

impl Entry {
    /// Acciones que cambian el equipo con --apply y piden confirmacion.
    fn destructive(self) -> bool {
        matches!(
            self,
            Entry::Start | Entry::Clean | Entry::ScheduleInstall | Entry::RevertAll
        )
    }
}

const ENTRIES: &[Entry] = &[
    Entry::Header("PROCESSO"),
    Entry::Start,
    Entry::Header("OPÇÕES"),
    Entry::ToggleSimple,
    Entry::ToggleRustdesk,
    Entry::ToggleOpencode,
    Entry::ToggleClean,
    Entry::TogglePolicies,
    Entry::ToggleAuditOnly,
    Entry::ToggleFirewall,
    Entry::ToggleBrowser,
    Entry::ToggleApply,
    Entry::Header("FERRAMENTAS"),
    Entry::Audit,
    Entry::Suspects,
    Entry::Clean,
    Entry::Evidence,
    Entry::History,
    Entry::Admins,
    Entry::Status,
    Entry::Events,
    Entry::ScheduleInstall,
    Entry::Update,
    Entry::RevertAll,
    Entry::Quit,
];

const SPINNER: &[char] = &['|', '/', '-', '\\'];

/// Mensajes del hilo lector del subproceso.
enum Msg {
    Line(String),
    /// Ambos flujos cerrados: el proceso ha terminado o esta terminando.
    Done,
}

/// Ventana de contraseña antes de una accion en modo real.
struct Confirm {
    entry: Entry,
    input: String,
    error: Option<&'static str>,
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
    /// Accion pendiente de confirmar con la contraseña (modo real).
    confirm: Option<Confirm>,
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
            Entry::Start => "Iniciar processo".to_string(),
            Entry::ToggleSimple => {
                format!("{} Modo simples (sem inventário)", chk(self.cfg.simple))
            }
            Entry::ToggleRustdesk => {
                format!("{} Desinstalar RustDesk", chk(self.cfg.uninstall_rustdesk))
            }
            Entry::ToggleOpencode => {
                format!("{} Desinstalar OpenCode", chk(self.cfg.uninstall_opencode))
            }
            Entry::ToggleClean => {
                format!("{} Limpar lixo (jogos e apps)", chk(self.cfg.clean_junk))
            }
            Entry::TogglePolicies => {
                format!("{} Políticas de execução", chk(self.cfg.apply_policies))
            }
            Entry::ToggleAuditOnly => {
                format!("  {} só auditar (não bloqueia)", chk(self.cfg.audit_only))
            }
            Entry::ToggleFirewall => {
                format!("{} Firewall: acesso remoto", chk(self.cfg.firewall))
            }
            Entry::ToggleBrowser => {
                format!("{} Sair das contas Google", chk(self.cfg.browser))
            }
            Entry::ToggleApply => format!("{} APLICAR DE FACTO", chk(self.cfg.apply)),
            Entry::Audit => "Auditar software instalado".to_string(),
            Entry::Suspects => "Ver software não autorizado".to_string(),
            Entry::Clean => "Limpar agora (desinstalar)".to_string(),
            Entry::Evidence => "Rasto: quem instalou".to_string(),
            Entry::History => "Histórico de desinstalações".to_string(),
            Entry::Admins => "Administradores locais".to_string(),
            Entry::Status => "Estado das proteções".to_string(),
            Entry::Events => "Eventos do AppLocker".to_string(),
            Entry::ScheduleInstall => "Instalar tarefa diária".to_string(),
            Entry::Update => "Procurar atualizações".to_string(),
            Entry::RevertAll => "Reverter tudo do AEGN".to_string(),
            Entry::Quit => "Sair".to_string(),
        }
    }

    fn help(&self, entry: Entry) -> &'static str {
        match entry {
            Entry::Header(_) => "",
            Entry::Start => "Executa o processo com as opções marcadas.",
            Entry::ToggleSimple => "Salta o inventário inicial e reduz a saída.",
            Entry::ToggleRustdesk => "Inclui o RustDesk (acesso remoto) na desinstalação.",
            Entry::ToggleOpencode => "Inclui o OpenCode na desinstalação.",
            Entry::ToggleClean => "Desinstala Roblox, Spotify, Lively Wallpaper, cursores personalizados, jogos (Steam, Riot, Epic, Battle.net, EA, Ubisoft, GOG) e acesso remoto não autorizado em todos os perfis e na Store, e apaga os restos. Tailscale, Git e o software do sistema ficam sempre.",
            Entry::TogglePolicies => "AppLocker: só se executam programas, scripts e MSI do Windows e de Program Files (os administradores, tudo). Também o que vem assinado pela Microsoft, Google (Chrome) e Mozilla (Firefox).",
            Entry::ToggleAuditOnly => "AppLocker em modo auditoria: não bloqueia, só regista o que bloquearia. Use-o primeiro em cada sala e reveja os 'Eventos do AppLocker'.",
            Entry::ToggleFirewall => "Bloqueia a saída pelas portas do RustDesk, AnyDesk e TeamViewer.",
            Entry::ToggleBrowser => "Chrome, Edge e Firefox apagam cookies (e as contas Google abertas) ao fechar, e portanto ao terminar a sessão do Windows. Desativa a sincronização e o início de sessão no Chrome.",
            Entry::ToggleApply => "Ativo: alterações reais (requer administrador e a senha do AEGN). Inativo: apenas simula.",
            Entry::Audit => "Lista o software instalado sem alterar nada.",
            Entry::Suspects => "Mostra só o que incumpre as regras da escola (Roblox, Spotify, Lively, cursores, jogos, acesso remoto).",
            Entry::Clean => "Desinstala esse software, apaga pastas de dados e cursores descarregados e repõe o cursor do Windows. Em simulação mostra o que faria.",
            Entry::Evidence => "Instaladores descarregados, eventos do Windows com a conta que instalou e programas de arranque automático.",
            Entry::History => "Quando, em que perfil e como foi desinstalado cada programa.",
            Entry::Admins => "Membros do grupo Administradores. Nenhum aluno deve lá estar.",
            Entry::Status => "AppLocker e AppIDSvc, regras de firewall, navegadores, tarefa agendada e senha.",
            Entry::Events => "Últimos bloqueios (e avisos de auditoria) registados pelo AppLocker.",
            Entry::ScheduleInstall => "Tarefa SYSTEM que volta a aplicar o processo no arranque e todos os dias. Requer o aegn.exe em Program Files.",
            Entry::Update => "Compara com o último release do GitHub. Com APLICAR, instala-o já pela tarefa AEGN-Atualizar (SYSTEM): sem administrador nem senha.",
            Entry::RevertAll => "Retira as regras AppLocker e de firewall, as diretivas de navegador do AEGN e a tarefa agendada.",
            Entry::Quit => "Fecha o AEGN Security.",
        }
    }

    /// Pasos que ejecutaria "Iniciar proceso" con la configuracion actual.
    fn plan(&self) -> Vec<&'static str> {
        let c = &self.cfg;
        [
            (!c.simple, "Inventário de software"),
            (!c.simple, "Administradores locais"),
            (c.uninstall_rustdesk, "Desinstalar o RustDesk"),
            (c.uninstall_opencode, "Desinstalar o OpenCode"),
            (c.clean_junk, "Limpar software não autorizado e restos"),
            (
                c.apply_policies && !c.audit_only,
                "AppLocker: bloquear as pastas dos utilizadores",
            ),
            (
                c.apply_policies && c.audit_only,
                "AppLocker em modo auditoria",
            ),
            (c.firewall, "Firewall: portas de acesso remoto"),
            (c.browser, "Navegadores: sair das contas ao fechar"),
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
                let mut a = vec!["executar"];
                for (on, flag) in [
                    (c.simple, "--simples"),
                    (!c.uninstall_rustdesk, "--sem-rustdesk"),
                    (!c.uninstall_opencode, "--sem-opencode"),
                    (!c.clean_junk, "--sem-limpeza"),
                    (!c.apply_policies, "--sem-politicas"),
                    (c.apply_policies && c.audit_only, "--so-auditoria"),
                    (!c.firewall, "--sem-firewall"),
                    (!c.browser, "--sem-navegador"),
                ] {
                    if on {
                        a.push(flag);
                    }
                }
                a
            }
            Entry::Audit => vec!["auditoria", "listar"],
            Entry::Suspects => vec!["auditoria", "suspeitos"],
            Entry::Clean => vec!["auditoria", "limpar"],
            Entry::Evidence => vec!["auditoria", "rasto"],
            Entry::History => vec!["auditoria", "historico"],
            Entry::Admins => vec!["auditoria", "admins"],
            Entry::Status => vec!["estado"],
            Entry::Events => vec!["politica", "eventos"],
            Entry::ScheduleInstall if c.audit_only => {
                vec!["tarefa", "instalar", "--so-auditoria"]
            }
            Entry::ScheduleInstall => vec!["tarefa", "instalar"],
            Entry::RevertAll => vec!["reverter"],
            Entry::Update => vec!["atualizar"],
            _ => return None,
        };
        // Atualizar com --aplicar não pede senha: só instala o release oficial.
        if c.apply && (entry.destructive() || entry == Entry::Update) {
            args.push("--aplicar");
        }
        Some(args)
    }

    /// Enter sobre una entrada: conmuta, pide la contraseña o lanza la accion.
    fn activate(&mut self, entry: Entry) -> Result<()> {
        if self.toggle(entry) {
            return Ok(());
        }
        if self.running() {
            self.notice = Some("Aguarde que a ação em curso termine.".into());
            return Ok(());
        }
        if entry == Entry::Start && self.plan().is_empty() {
            self.notice = Some("Não há nenhum passo marcado nas Opções.".into());
            return Ok(());
        }
        if self.cfg.apply && entry.destructive() {
            self.confirm = Some(Confirm {
                entry,
                input: String::new(),
                error: None,
            });
            return Ok(());
        }
        self.launch(entry, None)
    }

    /// Tecla dentro de la ventana de contraseña.
    fn confirm_key(&mut self, code: KeyCode) -> Result<()> {
        let Some(c) = self.confirm.as_mut() else {
            return Ok(());
        };
        match code {
            KeyCode::Esc => {
                self.confirm = None;
                self.notice = Some("Cancelado.".into());
            }
            KeyCode::Backspace => {
                c.input.pop();
            }
            KeyCode::Char(ch) => {
                c.input.push(ch);
                c.error = None;
            }
            KeyCode::Enter => {
                if auth::verify(&c.input)? {
                    let Confirm { entry, input, .. } = self.confirm.take().expect("confirm");
                    self.launch(entry, Some(input))?;
                } else {
                    c.input.clear();
                    c.error = Some("Senha incorreta.");
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Lanza la accion. `password` ya verificada, solo en modo real.
    fn launch(&mut self, entry: Entry, password: Option<String>) -> Result<()> {
        let Some(args) = self.args(entry) else {
            return Ok(());
        };
        let title = match entry {
            _ if args.contains(&"--aplicar") => format!("{} [REAL]", self.label(entry)),
            e if e.destructive() => format!("{} [simulação]", self.label(entry)),
            _ => self.label(entry),
        };
        self.notice = None;
        self.job = Some(spawn(title, &args, password.as_deref())?);
        Ok(())
    }

    /// Conmuta el flag de un toggle. Devuelve false si la entrada no es toggle.
    fn toggle(&mut self, entry: Entry) -> bool {
        let c = &mut self.cfg;
        let flag = match entry {
            Entry::ToggleSimple => &mut c.simple,
            Entry::ToggleRustdesk => &mut c.uninstall_rustdesk,
            Entry::ToggleOpencode => &mut c.uninstall_opencode,
            Entry::ToggleClean => &mut c.clean_junk,
            Entry::TogglePolicies => &mut c.apply_policies,
            Entry::ToggleAuditOnly => &mut c.audit_only,
            Entry::ToggleFirewall => &mut c.firewall,
            Entry::ToggleBrowser => &mut c.browser,
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
/// Sin terminal, la contraseña llega al subproceso por AEGN_SENHA.
fn spawn(title: String, args: &[&str], password: Option<&str>) -> Result<Job> {
    let exe = std::env::current_exe().context("não foi possível localizar o executável")?;
    let mut cmd = Command::new(exe);
    cmd.args(args)
        .env_remove(auth::ENV)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(pw) = password {
        cmd.env(auth::ENV, pw);
    }
    let mut child = cmd
        .spawn()
        .context("não foi possível lançar o subprocesso")?;

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

        if app.confirm.is_some() {
            app.confirm_key(key.code)?;
            continue;
        }

        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => {
                if app.running() {
                    app.notice = Some("Há uma ação em curso; aguarde que termine.".into());
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
            " SIMULAÇÃO ",
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
            rounded(Line::from(" AEGN Security · Escola AEGN "))
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
        draw_detail(f, app, body[1], rounded(Line::from(" Detalhe ")));
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
                key("Espaço"),
                txt(" marcar  "),
                key("Enter"),
                txt(" executar  "),
                key("a"),
                txt(" modo real  "),
                key("PgUp/PgDn ←→"),
                txt(" saída  "),
                key("c"),
                txt(" limpar  "),
                key("q"),
                txt(" sair"),
            ])
        }
    };
    f.render_widget(Paragraph::new(footer), rows[2]);

    if let Some(c) = &app.confirm {
        draw_confirm(f, app, c);
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
            | Entry::ToggleClean
            | Entry::TogglePolicies
            | Entry::ToggleAuditOnly
            | Entry::ToggleFirewall
            | Entry::ToggleBrowser
            | Entry::ToggleApply
    );
    if shows_plan {
        lines.push(Line::from(Span::styled(
            "Plano de execução",
            dim.add_modifier(Modifier::BOLD),
        )));
        let plan = app.plan();
        if plan.is_empty() {
            lines.push(Line::from(Span::styled(
                "  (nenhum passo marcado)",
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
            format!(" {} a executar ", SPINNER[tick % SPINNER.len()]),
            Color::Yellow,
        ),
        Some(Some(0)) => (" ok concluído ".to_string(), Color::Green),
        Some(Some(code)) => (format!(" x erro (código {code}) "), Color::Red),
        Some(None) => (" x interrompido ".to_string(), Color::Red),
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
        .title(Line::from(format!(" Saída · {} ", job.title)))
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
    let fg = if l.starts_with("[ok]") || l.starts_with("Política AEGN aplicada") {
        Color::Green
    } else if l.starts_with("[aviso]")
        || l.starts_with("[simulação]")
        || l.starts_with("NAO_ENCONTRADO")
    {
        Color::Yellow
    } else if l.starts_with("Error") || l.starts_with("[stderr]") || l.starts_with("[erro]") {
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

fn draw_confirm(f: &mut Frame, app: &App, c: &Confirm) {
    let area = f.area();
    let w = 58.min(area.width);
    let h = 10.min(area.height);
    let rect = Rect::new(
        area.x + (area.width - w) / 2,
        area.y + (area.height - h) / 2,
        w,
        h,
    );

    let key = |k: &'static str| {
        Span::styled(
            k,
            Style::default()
                .fg(Color::Black)
                .bg(Color::Gray)
                .add_modifier(Modifier::BOLD),
        )
    };
    let status = match c.error {
        Some(e) => Line::from(Span::styled(e, Style::default().fg(Color::Red))),
        None => Line::from(""),
    };
    let text = vec![
        Line::from(Span::styled(
            app.label(c.entry),
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from("Vão ser aplicadas alterações REAIS neste computador."),
        Line::from(""),
        Line::from(vec![
            Span::raw("Senha: "),
            Span::styled(
                format!("{:<20}", "*".repeat(c.input.chars().count().min(20))),
                Style::default().fg(Color::White).bg(Color::DarkGray),
            ),
        ]),
        status,
        Line::from(vec![
            key(" Enter "),
            Span::raw(" confirmar    "),
            key(" Esc "),
            Span::raw(" cancelar"),
        ]),
    ];
    let p = Paragraph::new(text).alignment(Alignment::Center).block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Double)
            .border_style(Style::default().fg(Color::Red))
            .title(Line::from(" Confirmar com a senha ").centered()),
    );
    f.render_widget(Clear, rect);
    f.render_widget(p, rect);
}
