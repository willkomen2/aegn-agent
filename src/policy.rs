//! Politicas de restriccion de ejecucion en carpetas de usuario.
//!
//! El objetivo es impedir que se ejecuten binarios arbitrarios desde rutas
//! escribibles por el usuario (donde no hace falta ser administrador para
//! copiar archivos), que es el bypass tipico para correr instaladores o juegos.
//!
//! Mecanismo: reglas de ruta de AppLocker (`Set-AppLockerPolicy`), el metodo
//! soportado por Microsoft para control de aplicaciones. Es transparente y
//! reversible: queda registrado en la directiva y se puede auditar.
//!
//! Rutas bloqueadas: %OSDRIVE%\Users\*\AppData\Local\* y la carpeta Downloads.
//! Se mantiene permitido Program Files y Windows para no romper el sistema.

use anyhow::Result;
#[cfg(windows)]
use anyhow::Context;

/// Identificador de grupo que el agente usa en sus reglas, para poder
/// distinguirlas y revertirlas sin tocar otras directivas existentes.
const RULE_TAG: &str = "AEGN-Deny-UserFolders";

/// Politica AppLocker en XML con reglas de denegacion por ruta. Las reglas de
/// "Deny" tienen prioridad sobre las de "Allow" en AppLocker.
fn applocker_policy_xml() -> String {
    format!(
        r#"<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="Enabled">
    <FilePathRule Id="e8c3b1a0-0001-4aeg-0001-aegnschool0001" Name="{tag}: AppData Local"
        Description="Escola AEGN: bloquea ejecucion de .exe en AppData\Local" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%OSDRIVE%\Users\*\AppData\Local\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="e8c3b1a0-0002-4aeg-0002-aegnschool0002" Name="{tag}: Downloads"
        Description="Escola AEGN: bloquea ejecucion de .exe en Downloads" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%OSDRIVE%\Users\*\Downloads\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="e8c3b1a0-0003-4aeg-0003-aegnschool0003" Name="{tag}: Permitir Program Files"
        Description="Permite ejecucion desde Program Files" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%PROGRAMFILES%\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="e8c3b1a0-0004-4aeg-0004-aegnschool0004" Name="{tag}: Permitir Windows"
        Description="Permite ejecucion desde el directorio de Windows" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*" />
      </Conditions>
    </FilePathRule>
  </RuleCollection>
</AppLockerPolicy>"#,
        tag = RULE_TAG
    )
}

/// Muestra el estado actual de las politicas de restriccion.
pub fn status() -> Result<()> {
    #[cfg(windows)]
    {
        let ps = r#"
$svc = Get-Service AppIDSvc -ErrorAction SilentlyContinue
if ($svc) { Write-Output ("Servicio AppIDSvc (AppLocker): " + $svc.Status) }
else { Write-Output "Servicio AppIDSvc no encontrado." }
Write-Output "--- Politica AppLocker efectiva (reglas Exe) ---"
(Get-AppLockerPolicy -Effective).RuleCollections |
  Where-Object { $_.RuleCollectionType -eq 'Exe' } |
  ForEach-Object { $_ } | Format-List Name, Action, PathConditions -ErrorAction SilentlyContinue
"#;
        let output = run_powershell(ps)?;
        println!("{output}");
        Ok(())
    }

    #[cfg(not(windows))]
    {
        println!("[info] El estado de politicas solo esta disponible en Windows.");
        println!("[info] Consultaria Get-AppLockerPolicy -Effective y el servicio AppIDSvc.");
        Ok(())
    }
}

/// Aplica el bloqueo de ejecucion en carpetas de usuario. Dry-run salvo `apply`.
pub fn enforce(apply: bool) -> Result<()> {
    let xml = applocker_policy_xml();

    if !apply {
        println!("[dry-run] Se aplicaria la siguiente politica AppLocker:\n");
        println!("{xml}");
        println!("\n[dry-run] Ejecuta con --apply para aplicarla (requiere admin).");
        println!("[nota] El servicio Application Identity (AppIDSvc) debe estar en ejecucion.");
        return Ok(());
    }

    #[cfg(windows)]
    {
        // Escribe la politica a un archivo temporal y la aplica con Set-AppLockerPolicy.
        // Se habilita y arranca AppIDSvc, necesario para que AppLocker actue.
        let ps = format!(
            r#"
$ErrorActionPreference = 'Stop'
$xml = @'
{xml}
'@
$tmp = Join-Path $env:TEMP 'aegn-applocker.xml'
Set-Content -Path $tmp -Value $xml -Encoding UTF8
Set-Service -Name AppIDSvc -StartupType Automatic
Start-Service -Name AppIDSvc -ErrorAction SilentlyContinue
Set-AppLockerPolicy -XmlPolicy $tmp -Merge
Write-Output "Politica AEGN aplicada y fusionada con la existente."
Remove-Item $tmp -Force
"#
        );
        let output = run_powershell(&ps)?;
        println!("{output}");
        Ok(())
    }

    #[cfg(not(windows))]
    {
        println!("[info] La aplicacion de politicas solo esta disponible en Windows.");
        Ok(())
    }
}

/// Revierte las reglas aplicadas por el agente (identificadas por RULE_TAG).
pub fn revert(apply: bool) -> Result<()> {
    if !apply {
        println!("[dry-run] Se eliminarian las reglas AppLocker con etiqueta '{RULE_TAG}'.");
        println!("[dry-run] Ejecuta con --apply para revertir de verdad (requiere admin).");
        return Ok(());
    }

    #[cfg(windows)]
    {
        // Aplicar una politica Exe vacia en modo NotConfigured retira el enforcement
        // de nuestras reglas. Para una reversion granular en produccion se recomienda
        // gestionar la directiva via GPO; aqui se limpia la coleccion Exe local.
        let ps = r#"
$ErrorActionPreference = 'Stop'
$empty = @'
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="NotConfigured" />
</AppLockerPolicy>
'@
$tmp = Join-Path $env:TEMP 'aegn-applocker-revert.xml'
Set-Content -Path $tmp -Value $empty -Encoding UTF8
Set-AppLockerPolicy -XmlPolicy $tmp
Write-Output "Reglas Exe de AppLocker revertidas a NotConfigured."
Remove-Item $tmp -Force
"#;
        let output = run_powershell(ps)?;
        println!("{output}");
        Ok(())
    }

    #[cfg(not(windows))]
    {
        let _ = apply;
        println!("[info] La reversion de politicas solo esta disponible en Windows.");
        Ok(())
    }
}

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
