//! `aegn instalar`: instalar un programa en un equipo protegido.
//!
//! AppLocker bloquea a los alumnos los instaladores de Transferencias o de una
//! pen USB. Con la contraseña del AEGN (la pide main antes de llegar aqui) el
//! instalador se lanza elevado: Windows abre el UAC y pide una cuenta de
//! administrador. El proceso elevado ya corre como administrador, al que
//! AppLocker lo permite todo, asi que solo instala quien tenga las dos cosas.

use anyhow::{bail, Context, Result};
use std::path::Path;

/// Lanza el instalador `file` (.exe o .msi) elevado y espera a que termine.
pub fn run(file: &Path) -> Result<()> {
    let path = std::fs::canonicalize(file)
        .with_context(|| format!("não foi encontrado o ficheiro {}", file.display()))?;
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    if !matches!(ext.as_str(), "exe" | "msi") {
        bail!("só se instalam ficheiros .exe ou .msi.");
    }
    // canonicalize devuelve \\?\C:\..., que Start-Process y msiexec no aceptan.
    let shown = path.display().to_string();
    let shown = shown.strip_prefix(r"\\?\").unwrap_or(&shown).to_string();
    println!("A abrir o instalador {shown}...");
    println!("O Windows vai pedir uma conta de administrador.");

    #[cfg(windows)]
    {
        print!("{}", crate::ps::run(&script(&shown, &ext))?);
        Ok(())
    }

    #[cfg(not(windows))]
    {
        println!("[info] A instalação só está disponível no Windows.");
        let _ = script(&shown, &ext);
        Ok(())
    }
}

/// PowerShell que lanza el instalador con -Verb RunAs (UAC).
fn script(path: &str, ext: &str) -> String {
    let p = path.replace('\'', "''");
    let start = if ext == "msi" {
        format!("Start-Process msiexec.exe -Verb RunAs -Wait -PassThru -ArgumentList ('/i \"' + '{p}' + '\"')")
    } else {
        format!("Start-Process -FilePath '{p}' -Verb RunAs -Wait -PassThru")
    };
    format!(
        r#"try {{ $p = {start} }}
catch {{
  if ($_.Exception.InnerException.NativeErrorCode -eq 1223 -or "$_" -match 'cancel') {{ Write-Output 'Instalação cancelada no UAC.'; exit 0 }}
  throw
}}
Write-Output ("O instalador terminou com o código " + $p.ExitCode + ".")"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msi_va_por_msiexec_y_escapa_comillas() {
        let s = script(r"C:\Users\O'Neil\setup.msi", "msi");
        assert!(s.contains("msiexec.exe -Verb RunAs"));
        assert!(s.contains("O''Neil"));
        assert!(
            script(r"C:\x\setup.exe", "exe").contains("-FilePath 'C:\\x\\setup.exe' -Verb RunAs")
        );
    }

    #[test]
    fn rechaza_otras_extensiones() {
        let tmp = std::env::temp_dir().join("aegn-test-instalar.txt");
        std::fs::write(&tmp, "x").unwrap();
        assert!(run(&tmp).is_err());
        std::fs::remove_file(tmp).ok();
    }
}
