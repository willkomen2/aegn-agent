//! aegn-agent — Agente de administracion y seguridad de endpoints de la Escola AEGN.
//!
//! Herramienta interna para que el administrador de sistemas mantenga las maquinas
//! de la escuela como material de estudio: auditar e desinstalar software no
//! autorizado y aplicar politicas de restriccion de ejecucion en carpetas de
//! usuario, usando mecanismos nativos de Windows (winget, AppLocker, directivas).
//!
//! Diseño:
//! - Todas las acciones destructivas son dry-run por defecto; hay que pasar
//!   `--apply` para ejecutarlas de verdad.
//! - Las operaciones de sistema requieren consola de administrador en Windows.
//! - Sin argumentos abre el menu TUI interactivo.

mod audit;
mod firewall;
mod github;
mod policy;
mod process;
#[cfg(windows)]
mod ps;
mod schedule;
mod tui;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "aegn",
    version,
    about = "Agente de administracion y seguridad de endpoints - Escola AEGN",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Abre el menu interactivo (TUI con banner ASCII). Es el modo por defecto.
    Menu,

    /// Ejecuta el proceso de mantenimiento completo (version no interactiva).
    Run {
        /// Modo simple: omite el inventario previo.
        #[arg(long)]
        simple: bool,
        /// No desinstalar RustDesk.
        #[arg(long)]
        no_rustdesk: bool,
        /// No desinstalar OpenCode.
        #[arg(long)]
        no_opencode: bool,
        /// No aplicar politicas de ejecucion.
        #[arg(long)]
        no_policies: bool,
        /// AppLocker en modo auditoria: registra lo que bloquearia, sin bloquear.
        #[arg(long)]
        audit_only: bool,
        /// No crear las reglas de firewall contra herramientas de acceso remoto.
        #[arg(long)]
        no_firewall: bool,
        /// Aplica cambios reales (por defecto es dry-run).
        #[arg(long)]
        apply: bool,
    },

    /// Auditoria y remocion de software no autorizado.
    Audit {
        #[command(subcommand)]
        action: AuditAction,
    },

    /// Politicas de restriccion de ejecucion en carpetas de usuario.
    Policy {
        #[command(subcommand)]
        action: PolicyAction,
    },

    /// Bloqueo saliente de herramientas de acceso remoto en el firewall.
    Firewall {
        #[command(subcommand)]
        action: FirewallAction,
    },

    /// Tarea programada (SYSTEM) que reaplica el proceso a diario.
    Schedule {
        #[command(subcommand)]
        action: ScheduleAction,
    },

    /// Estado de todas las protecciones: AppLocker, firewall y tarea.
    Status,

    /// Deshace todo lo aplicado por el agente (AppLocker, firewall y tarea).
    Revert {
        #[arg(long)]
        apply: bool,
    },

    /// Interaccion con GitHub (gestion del repositorio del proyecto).
    Gh {
        #[command(subcommand)]
        action: GhAction,
    },
}

#[derive(Subcommand)]
enum AuditAction {
    /// Lista el software instalado detectado en la maquina.
    List,
    /// Lista los miembros del grupo local de Administradores.
    Admins,
    /// Desinstala un programa no autorizado por nombre (ej: RustDesk, OpenCode).
    Remove {
        /// Nombre o identificador del paquete a desinstalar.
        name: String,
        /// Ejecuta la desinstalacion de verdad (por defecto es dry-run).
        #[arg(long)]
        apply: bool,
    },
}

#[derive(Subcommand)]
enum PolicyAction {
    /// Muestra el estado actual de las politicas de restriccion.
    Status,
    /// Aplica el bloqueo de ejecucion en AppData\Local y Downloads.
    Enforce {
        /// Aplica la politica de verdad (por defecto genera y muestra sin aplicar).
        #[arg(long)]
        apply: bool,
        /// Modo auditoria: registra lo que bloquearia, sin bloquear.
        #[arg(long)]
        audit_only: bool,
    },
    /// Revierte las politicas de restriccion aplicadas por el agente.
    Revert {
        #[arg(long)]
        apply: bool,
    },
    /// Ultimos eventos de AppLocker (bloqueos y auditoria).
    Events {
        /// Numero maximo de eventos.
        #[arg(long, default_value_t = 30)]
        max: u32,
    },
}

#[derive(Subcommand)]
enum FirewallAction {
    /// Muestra las reglas AEGN y el estado de los perfiles del firewall.
    Status,
    /// Crea las reglas de bloqueo saliente.
    Enforce {
        #[arg(long)]
        apply: bool,
    },
    /// Elimina las reglas AEGN.
    Revert {
        #[arg(long)]
        apply: bool,
    },
}

#[derive(Subcommand)]
enum ScheduleAction {
    /// Estado de la tarea y ultimas lineas del log.
    Status,
    /// Registra la tarea (requiere aegn.exe dentro de Program Files).
    Install {
        #[arg(long)]
        apply: bool,
        /// La tarea aplica AppLocker en modo auditoria.
        #[arg(long)]
        audit_only: bool,
    },
    /// Elimina la tarea.
    Remove {
        #[arg(long)]
        apply: bool,
    },
}

#[derive(Subcommand)]
enum GhAction {
    /// Verifica el token (GITHUB_TOKEN) e imprime el usuario autenticado.
    Whoami,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        None | Some(Command::Menu) => tui::run()?,
        Some(Command::Run {
            simple,
            no_rustdesk,
            no_opencode,
            no_policies,
            audit_only,
            no_firewall,
            apply,
        }) => process::run(&process::ProcessConfig {
            simple,
            uninstall_rustdesk: !no_rustdesk,
            uninstall_opencode: !no_opencode,
            apply_policies: !no_policies,
            audit_only,
            firewall: !no_firewall,
            apply,
        })?,
        Some(Command::Audit { action }) => match action {
            AuditAction::List => audit::list()?,
            AuditAction::Admins => audit::admins()?,
            AuditAction::Remove { name, apply } => audit::remove(&name, apply)?,
        },
        Some(Command::Policy { action }) => match action {
            PolicyAction::Status => policy::status()?,
            PolicyAction::Enforce { apply, audit_only } => policy::enforce(apply, audit_only)?,
            PolicyAction::Revert { apply } => policy::revert(apply)?,
            PolicyAction::Events { max } => policy::events(max)?,
        },
        Some(Command::Firewall { action }) => match action {
            FirewallAction::Status => firewall::status()?,
            FirewallAction::Enforce { apply } => firewall::enforce(apply)?,
            FirewallAction::Revert { apply } => firewall::revert(apply)?,
        },
        Some(Command::Schedule { action }) => match action {
            ScheduleAction::Status => schedule::status()?,
            ScheduleAction::Install { apply, audit_only } => schedule::install(apply, audit_only)?,
            ScheduleAction::Remove { apply } => schedule::remove(apply)?,
        },
        Some(Command::Status) => process::status_all()?,
        Some(Command::Revert { apply }) => process::revert_all(apply)?,
        Some(Command::Gh { action }) => match action {
            GhAction::Whoami => github::whoami()?,
        },
    }

    Ok(())
}
