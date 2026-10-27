//! Auditoria y remocion de software no autorizado.
//!
//! En Windows se apoya en mecanismos legitimos:
//! - Inventario: claves de desinstalacion del registro (`Get-ItemProperty` sobre
//!   `...\Uninstall`), que es la misma fuente que usa "Programas y caracteristicas".
//! - Desinstalacion: `winget uninstall` cuando el paquete esta gestionado, con
//!   fallback a la `UninstallString` registrada por el propio instalador.
//!
//! Toda remocion es dry-run salvo que se pase `apply = true`.

use anyhow::Result;
#[cfg(windows)]
use anyhow::Context;

/// Lista el software instalado detectado en la maquina.
pub fn list() -> Result<()> {
    #[cfg(windows)]
    {
        // Consulta las tres ubicaciones habituales del registro (64-bit, 32-bit y
        // por-usuario) y emite nombre + version + publisher.
        let ps = r#"
$paths = @(
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
  'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
Get-ItemProperty $paths -ErrorAction SilentlyContinue |
  Where-Object { $_.DisplayName } |
  Select-Object DisplayName, DisplayVersion, Publisher |
  Sort-Object DisplayName |
  Format-Table -AutoSize
"#;
        let output = run_powershell(ps)?;
        println!("{output}");
        Ok(())
    }

    #[cfg(not(windows))]
    {
        println!("[info] El inventario de software solo esta disponible en Windows.");
        println!("[info] En el endpoint ejecutaria: Get-ItemProperty sobre las claves Uninstall del registro.");
        Ok(())
    }
}

/// Desinstala un programa no autorizado por nombre. Dry-run salvo `apply`.
pub fn remove(name: &str, apply: bool) -> Result<()> {
    if !apply {
        println!("[dry-run] Se desinstalaria el software que coincida con: '{name}'");
        println!("[dry-run] Ejecuta con --apply para desinstalar de verdad (requiere admin).");
        return Ok(());
    }

    #[cfg(windows)]
    {
        println!("[accion] Intentando desinstalar '{name}' via winget...");
        // winget maneja la mayoria del software moderno de forma silenciosa.
        let winget = std::process::Command::new("winget")
            .args([
                "uninstall",
                "--name",
                name,
                "--silent",
                "--accept-source-agreements",
                "--disable-interactivity",
            ])
            .status();

        match winget {
            Ok(status) if status.success() => {
                println!("[ok] '{name}' desinstalado via winget.");
                return Ok(());
            }
            _ => {
                println!("[info] winget no completo la operacion; probando UninstallString del registro.");
            }
        }

        // Fallback: recuperar la UninstallString registrada por el instalador.
        let ps = format!(
            r#"
$name = '{}'
$paths = @(
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
  'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$app = Get-ItemProperty $paths -ErrorAction SilentlyContinue |
  Where-Object {{ $_.DisplayName -like "*$name*" }} | Select-Object -First 1
if (-not $app) {{ Write-Output 'NOT_FOUND'; exit 1 }}
Write-Output ("TARGET=" + $app.DisplayName)
$cmd = $app.QuietUninstallString
if (-not $cmd) {{ $cmd = $app.UninstallString }}
if (-not $cmd) {{ Write-Output 'NO_UNINSTALL_STRING'; exit 1 }}
Write-Output ("CMD=" + $cmd)
Start-Process -FilePath "cmd.exe" -ArgumentList "/c", $cmd -Wait -NoNewWindow
"#,
            name.replace('\'', "''")
        );
        let output = run_powershell(&ps)?;
        println!("{output}");
        Ok(())
    }

    #[cfg(not(windows))]
    {
        let _ = apply;
        println!("[info] La desinstalacion solo esta disponible en Windows ('{name}').");
        Ok(())
    }
}

/// Ejecuta un script de PowerShell y devuelve su salida combinada.
#[cfg(windows)]
fn run_powershell(script: &str) -> Result<String> {
    let output = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .context("no se pudo invocar powershell")?;

    let mut combined = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.trim().is_empty() {
        combined.push_str("\n[stderr] ");
        combined.push_str(&stderr);
    }
    Ok(combined)
}
