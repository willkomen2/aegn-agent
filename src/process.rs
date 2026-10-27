//! Orquestador del "proceso" de mantenimiento que ejecuta el agente.
//!
//! Reune en una sola rutina los pasos que el administrador quiere lanzar de
//! golpe desde el menu (o desde `aegn run`): inventario, desinstalacion de
//! software no autorizado y aplicacion de politicas de ejecucion.
//!
//! Respeta el principio de dry-run: nada se aplica de verdad salvo `apply=true`.

use crate::{audit, policy};
use anyhow::Result;

/// Configuracion de una ejecucion del proceso. La arma el menu (toggles) o la
/// CLI (flags). Es el unico punto donde se decide QUE se hace.
pub struct ProcessConfig {
    /// Modo simple: omite el inventario previo y reduce la salida.
    pub simple: bool,
    pub uninstall_rustdesk: bool,
    pub uninstall_opencode: bool,
    pub apply_policies: bool,
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
        println!("[DRY-RUN] Solo se muestra que se haria. Activa 'Aplicar de verdad' para ejecutar.");
    }
    println!();

    if !cfg.simple {
        println!("-- Inventario de software instalado --");
        audit::list()?;
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
        policy::enforce(cfg.apply)?;
        println!();
    }

    println!("================ Proceso finalizado ================");
    Ok(())
}
