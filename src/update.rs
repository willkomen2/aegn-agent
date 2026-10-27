//! Actualizacion automatica desde los releases de GitHub.
//!
//! Quien actualiza de verdad es `atualizar.ps1`, que el MSI instala junto a
//! `aegn.exe` y ejecuta la tarea `AEGN-Atualizar` como SYSTEM: por eso no pide
//! UAC ni la contraseña. Este modulo solo consulta la ultima version y, con
//! `--aplicar`, lanza esa tarea (los usuarios autenticados tienen permiso de
//! ejecutarla). No instala el MSI desde aqui: `aegn.exe` estaria en uso
//! mientras el MSI intenta sustituirlo.
//!
//! La ultima version sale del `SHA256SUMS.txt` del ultimo release, a traves de
//! `releases/latest/download/`, que no cuenta para el limite de la API.

use anyhow::Result;

/// Repositorio de GitHub de donde salen los releases.
pub const REPO: &str = "willkomen2/aegn-agent";
const TASK: &str = "AEGN-Atualizar";
const VERSION: &str = env!("CARGO_PKG_VERSION");

// En Linux solo se usan en los tests: la consulta es de Windows.
#[cfg_attr(not(windows), allow(dead_code))]
/// Version del MSI listado en un `SHA256SUMS.txt` del release.
fn version_in_sums(sums: &str) -> Option<String> {
    sums.lines().find_map(|line| {
        let mut parts = line.split_whitespace();
        let (hash, name) = (parts.next()?, parts.next()?);
        if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        let v = name
            .strip_prefix("AEGN-Security-")?
            .strip_suffix("-x64.msi")?;
        parse(v).map(|_| v.to_string())
    })
}

#[cfg_attr(not(windows), allow(dead_code))]
/// "1.2.3" → (1, 2, 3).
fn parse(v: &str) -> Option<(u64, u64, u64)> {
    let mut it = v.trim().trim_start_matches('v').split('.');
    let n = (
        it.next()?.parse().ok()?,
        it.next()?.parse().ok()?,
        it.next()?.parse().ok()?,
    );
    it.next().is_none().then_some(n)
}

#[cfg_attr(not(windows), allow(dead_code))]
/// true si `remote` es mas reciente que `local`.
fn is_newer(remote: &str, local: &str) -> bool {
    matches!((parse(remote), parse(local)), (Some(r), Some(l)) if r > l)
}

/// Consulta la ultima version y, con `apply`, lanza la tarea de actualizacion.
pub fn run(apply: bool) -> Result<()> {
    #[cfg(windows)]
    {
        let ps = format!(
            "[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12\n\
             $w = New-Object Net.WebClient\n\
             $w.Headers.Add('User-Agent', 'aegn-atualizar')\n\
             $w.DownloadString('https://github.com/{REPO}/releases/latest/download/SHA256SUMS.txt')"
        );
        let sums = crate::ps::run(&ps).map_err(|e| {
            anyhow::anyhow!("não foi possível consultar os releases de github.com/{REPO}: {e}")
        })?;
        let Some(latest) = version_in_sums(&sums) else {
            anyhow::bail!("o último release de github.com/{REPO} não tem nenhum MSI no SHA256SUMS.txt");
        };
        println!("Versão instalada: {VERSION}");
        println!("Último release:   {latest}");
        if !is_newer(&latest, VERSION) {
            println!("[ok] O AEGN Security está atualizado.");
            return Ok(());
        }
        if !apply {
            println!("[simulação] Há uma versão nova. A tarefa {TASK} instala-a sozinha (no arranque e");
            println!("[simulação] por volta das 13:00). Para já: aegn atualizar --aplicar (não requer administrador).");
            return Ok(());
        }
        let out = std::process::Command::new("schtasks")
            .args(["/Run", "/TN", TASK])
            .output()?;
        if !out.status.success() {
            anyhow::bail!(
                "não foi possível lançar a tarefa {TASK}: {}\
                 A tarefa é registada pelo instalador MSI (versão 0.3.0 ou posterior).",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        println!("[ok] Atualização para a {latest} iniciada em segundo plano (como SYSTEM).");
        println!("     Acompanhe com: aegn atualizar estado");
        Ok(())
    }

    #[cfg(not(windows))]
    {
        let _ = apply;
        println!("[info] As atualizações automáticas só estão disponíveis no Windows.");
        println!("       Versão {VERSION}; releases em https://github.com/{REPO}/releases");
        Ok(())
    }
}

/// Estado de la tarea de actualizacion y ultimas lineas de su log.
pub fn status() -> Result<()> {
    #[cfg(windows)]
    {
        let log = std::env::current_exe()?
            .parent()
            .map(|d| d.join("logs").join("atualizacao.log").display().to_string())
            .unwrap_or_default()
            .replace('\'', "''");
        let ps = format!(
            r#"
$t = Get-ScheduledTask -TaskName '{TASK}' -ErrorAction SilentlyContinue
if (-not $t) {{ Write-Output 'Tarefa {TASK} não instalada (instale o MSI 0.3.0 ou posterior).'; exit 0 }}
$i = $t | Get-ScheduledTaskInfo
Write-Output ("Tarefa {TASK}: " + $t.State + "  (versão {VERSION}, github.com/{REPO})")
Write-Output ("  Última execução: " + $i.LastRunTime + "  resultado: " + $i.LastTaskResult)
Write-Output ("  Próxima: " + $i.NextRunTime)
if (Test-Path '{log}') {{ Write-Output '--- Últimas linhas do registo ---'; Get-Content '{log}' -Tail 10 }}
"#
        );
        print!("{}", crate::ps::run(&ps)?);
        Ok(())
    }

    #[cfg(not(windows))]
    {
        println!("[info] A tarefa {TASK} só existe no Windows.");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lee_la_version_del_msi_en_sha256sums() {
        let h = "a".repeat(64);
        let sums = format!(
            "{h}  aegn.exe\n{h}  AEGN-Security-0.4.1-windows.zip\n{h}  AEGN-Security-0.4.1-x64.msi\n"
        );
        assert_eq!(version_in_sums(&sums).as_deref(), Some("0.4.1"));
        assert_eq!(version_in_sums("xyz  AEGN-Security-0.4.1-x64.msi"), None);
        assert_eq!(version_in_sums(""), None);
    }

    #[test]
    fn compara_versiones_por_numero() {
        assert!(is_newer("0.10.0", "0.9.9"));
        assert!(is_newer("1.0.0", "0.3.0"));
        assert!(!is_newer("0.3.0", "0.3.0"));
        assert!(!is_newer("0.2.9", "0.3.0"));
        assert!(!is_newer("basura", "0.3.0"));
    }
}
