//! Ejecucion de scripts de PowerShell (solo Windows).

use anyhow::{bail, Context, Result};

/// Ejecuta un script de PowerShell y devuelve stdout + stderr. Falla si el
/// script termina con codigo distinto de 0, para que un error real (permisos,
/// cmdlet inexistente, politica rechazada) no se reporte como exito.
pub fn run(script: &str) -> Result<String> {
    // Salida en UTF-8 para no romper los acentos de la consola OEM, y sin barras
    // de progreso que ensucien la salida capturada.
    let script = format!(
        "[Console]::OutputEncoding = [Text.Encoding]::UTF8\n$ProgressPreference = 'SilentlyContinue'\n{script}"
    );
    let output = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .context("não foi possível invocar o PowerShell")?;

    let mut combined = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.trim().is_empty() {
        combined.push_str("\n[stderr] ");
        combined.push_str(&stderr);
    }
    if !output.status.success() {
        bail!(
            "o PowerShell terminou com {}:\n{}",
            output.status,
            combined.trim()
        );
    }
    Ok(combined)
}
