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
mod github;
mod policy;
mod process;
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
    },
    /// Revierte las politicas de restriccion aplicadas por el agente.
    Revert {
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
            apply,
        }) => process::run(&process::ProcessConfig {
            simple,
            uninstall_rustdesk: !no_rustdesk,
            uninstall_opencode: !no_opencode,
            apply_policies: !no_policies,
            apply,
        })?,
        Some(Command::Audit { action }) => match action {
            AuditAction::List => audit::list()?,
            AuditAction::Remove { name, apply } => audit::remove(&name, apply)?,
        },
        Some(Command::Policy { action }) => match action {
            PolicyAction::Status => policy::status()?,
            PolicyAction::Enforce { apply } => policy::enforce(apply)?,
            PolicyAction::Revert { apply } => policy::revert(apply)?,
        },
        Some(Command::Gh { action }) => match action {
            GhAction::Whoami => github::whoami()?,
        },
    }

    Ok(())
}
