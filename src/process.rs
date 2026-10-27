//! Orquestador del "proceso" de mantenimiento que ejecuta el agente.
//!
//! Reune en una sola rutina los pasos que el administrador quiere lanzar de
//! golpe desde el menu (o desde `aegn run`): inventario, desinstalacion de
//! software no autorizado, politicas de ejecucion y firewall.
//!
//! Respeta el principio de dry-run: nada se aplica de verdad salvo `apply=true`.

use crate::{audit, firewall, policy, schedule};
use anyhow::Result;

/// Configuracion de una ejecucion del proceso. La arma el menu (toggles) o la
/// CLI (flags). Es el unico punto donde se decide QUE se hace.
pub struct ProcessConfig {
    /// Modo simple: omite el inventario previo y reduce la salida.
    pub simple: bool,
    pub uninstall_rustdesk: bool,
    pub uninstall_opencode: bool,
    pub apply_policies: bool,
    /// AppLocker en modo AuditOnly: registra pero no bloquea.
    pub audit_only: bool,
    /// Bloqueo saliente de puertos de herramientas de acceso remoto.
    pub firewall: bool,
    /// true = cambios reales (requiere admin); false = dry-run (por defecto).
    pub apply: bool,
}

impl Default for ProcessConfig {
    fn default() -> Self {
        Self {
            simple: false,
            uninstall_rustdesk: true,
            uninstall_opencode: true,
            apply_policies: true,
            audit_only: false,
            firewall: true,
            apply: false,
        }
    }
}

/// Ejecuta el proceso segun la configuracion dada.
pub fn run(cfg: &ProcessConfig) -> Result<()> {
    println!("================ Proceso AEGN ================");
    if cfg.apply {
        println!("[MODO REAL] Se aplicaran cambios. Requiere consola de administrador.");
    } else {
        println!(
            "[DRY-RUN] Solo se muestra que se haria. Activa 'Aplicar de verdad' para ejecutar."
        );
    }
    println!();

    if !cfg.simple {
        println!("-- Inventario de software instalado --");
        audit::list()?;
        println!();
        println!("-- Administradores locales --");
        audit::admins()?;
        println!();
    }

    if cfg.uninstall_rustdesk {
        println!("-- Desinstalar RustDesk --");
        audit::remove("RustDesk", cfg.apply)?;
        println!();
    }

    if cfg.uninstall_opencode {
        println!("-- Desinstalar OpenCode --");
        audit::remove("OpenCode", cfg.apply)?;
        println!();
    }

    if cfg.apply_policies {
        println!("-- Politicas de restriccion de ejecucion --");
        policy::enforce(cfg.apply, cfg.audit_only)?;
        println!();
    }

    if cfg.firewall {
        println!("-- Firewall: acceso remoto --");
        firewall::enforce(cfg.apply)?;
        println!();
    }

    println!("================ Proceso finalizado ================");
    Ok(())
}

/// Estado de todas las protecciones que gestiona el agente.
pub fn status_all() -> Result<()> {
    println!("-- AppLocker --");
    policy::status()?;
    println!();
    println!("-- Firewall --");
    firewall::status()?;
    println!();
    println!("-- Tarea programada --");
    schedule::status()
}

/// Deshace todo lo que aplica el agente: reglas AppLocker, reglas de firewall
/// y tarea programada. No reinstala el software desinstalado.
pub fn revert_all(apply: bool) -> Result<()> {
    println!("-- AppLocker --");
    policy::revert(apply)?;
    println!();
    println!("-- Firewall --");
    firewall::revert(apply)?;
    println!();
    println!("-- Tarea programada --");
    schedule::remove(apply)?;
    if !apply {
        println!();
        println!("[dry-run] Ejecuta con --apply para revertir de verdad (requiere admin).");
    }
    Ok(())
}
