//! Orquestador del "proceso" de mantenimiento que ejecuta el agente.
//!
//! Reune en una sola rutina los pasos que el administrador quiere lanzar de
//! golpe desde el menu (o desde `aegn executar`): inventario, desinstalacion de
//! software no autorizado, politicas de ejecucion y firewall.
//!
//! Respeta el principio de dry-run: nada se aplica de verdad salvo `apply=true`.

use crate::{audit, auth, firewall, policy, schedule};
use anyhow::Result;

/// Configuracion de una ejecucion del proceso. La arma el menu (toggles) o la
/// CLI (flags). Es el unico punto donde se decide QUE se hace.
pub struct ProcessConfig {
    /// Modo simple: omite el inventario previo y reduce la salida.
    pub simple: bool,
    pub uninstall_rustdesk: bool,
    pub uninstall_opencode: bool,
    /// Limpieza de la lista negra (Roblox, Spotify, Lively, cursores...) y de
    /// sus restos, ademas del cursor personalizado.
    pub clean_junk: bool,
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
            clean_junk: true,
            apply_policies: true,
            audit_only: false,
            firewall: true,
            apply: false,
        }
    }
}

/// Ejecuta el proceso segun la configuracion dada.
pub fn run(cfg: &ProcessConfig) -> Result<()> {
    println!("================ Processo AEGN Security ================");
    if cfg.apply {
        println!("[MODO REAL] Vão ser aplicadas alterações. Requer consola de administrador.");
    } else {
        println!(
            "[SIMULAÇÃO] Apenas se mostra o que seria feito. Ative 'Aplicar de facto' para executar."
        );
    }
    println!();

    if !cfg.simple {
        println!("-- Inventário do software instalado --");
        audit::list()?;
        println!();
        println!("-- Administradores locais --");
        audit::admins()?;
        println!();
    }

    // Un programa que falla no detiene la limpieza de los demas.
    let mut targets: Vec<&str> = Vec::new();
    if cfg.uninstall_rustdesk {
        targets.push("RustDesk");
    }
    if cfg.uninstall_opencode {
        targets.push("OpenCode");
    }
    let mut failed = Vec::new();
    for name in &targets {
        println!("-- Desinstalar: {name} --");
        if let Err(e) = audit::remove(name, cfg.apply) {
            println!("[erro] {e:#}");
            failed.push(*name);
        }
        println!();
    }

    if cfg.clean_junk {
        println!("-- Limpeza: software não autorizado e restos --");
        if let Err(e) = audit::clean(cfg.apply) {
            println!("[erro] {e:#}");
            failed.push("lista negra");
        }
        println!();
    }

    if cfg.apply_policies {
        println!("-- Políticas de restrição de execução --");
        policy::enforce(cfg.apply, cfg.audit_only)?;
        println!();
    }

    if cfg.firewall {
        println!("-- Firewall: acesso remoto --");
        firewall::enforce(cfg.apply)?;
        println!();
    }

    if !failed.is_empty() {
        println!(
            "[aviso] Não foi possível desinstalar: {}",
            failed.join(", ")
        );
    }
    if cfg.apply && (!targets.is_empty() || cfg.clean_junk) {
        println!("Histórico de desinstalações: aegn auditoria historico");
    }
    println!("================ Processo concluído ================");
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
    println!("-- Tarefa agendada --");
    schedule::status()?;
    println!();
    println!("-- Atualização automática --");
    crate::update::status()?;
    println!();
    println!("-- Senha de administração --");
    auth::status()
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
    println!("-- Tarefa agendada --");
    schedule::remove(apply)?;
    if !apply {
        println!();
        println!(
            "[simulação] Execute com --aplicar para reverter de facto (requer administrador)."
        );
    }
    Ok(())
}
