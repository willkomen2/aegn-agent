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

/// Identificador de grupo que el agente usa en sus reglas, para poder
/// distinguirlas y revertirlas sin tocar otras directivas existentes.
const RULE_TAG: &str = "AEGN-Deny-UserFolders";

/// Politica AppLocker en XML con reglas de denegacion por ruta. Las reglas de
/// "Deny" tienen prioridad sobre las de "Allow" en AppLocker.
///
/// Con la coleccion Exe en modo Enabled, todo lo que no case con un Allow queda
/// bloqueado; por eso se incluyen las reglas por defecto de AppLocker (Windows,
/// Program Files y "todo" para Administradores). Los Deny aplican a Everyone,
/// administradores incluidos.
fn applocker_policy_xml() -> String {
    format!(
        r#"<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="Enabled">
    <FilePathRule Id="ae6e0000-0000-4000-8000-000000000001" Name="{tag}: AppData Local"
        Description="Escola AEGN: bloquea ejecucion de .exe en AppData\Local" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%OSDRIVE%\Users\*\AppData\Local\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="ae6e0000-0000-4000-8000-000000000002" Name="{tag}: Downloads"
        Description="Escola AEGN: bloquea ejecucion de .exe en Downloads" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%OSDRIVE%\Users\*\Downloads\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="ae6e0000-0000-4000-8000-000000000003" Name="{tag}: Permitir Program Files"
        Description="Permite ejecucion desde Program Files" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%PROGRAMFILES%\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="ae6e0000-0000-4000-8000-000000000004" Name="{tag}: Permitir Windows"
        Description="Permite ejecucion desde el directorio de Windows" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="ae6e0000-0000-4000-8000-000000000005" Name="{tag}: Permitir Administradores"
        Description="Los administradores pueden ejecutar desde cualquier ruta (regla por defecto de AppLocker)" UserOrGroupSid="S-1-5-32-544" Action="Allow">
      <Conditions>
        <FilePathCondition Path="*" />
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
        print!("{}", crate::ps::run(ps)?);
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
        // Quita primero las reglas AEGN de una ejecucion anterior (asi se puede
        // repetir sin duplicar Ids) y fusiona las nuevas con la politica local.
        let ps = format!(
            r#"
$ErrorActionPreference = 'Stop'
{strip}
$xml = @'
{xml}
'@
$tmp = Join-Path $env:TEMP 'aegn-applocker.xml'
Set-Content -Path $tmp -Value $xml -Encoding UTF8
Set-AppLockerPolicy -XmlPolicy $tmp -Merge
Remove-Item $tmp -Force
Write-Output "Politica AEGN aplicada y fusionada con la existente."
{service}
"#,
            strip = strip_script(),
            service = SERVICE_PS,
        );
        print!("{}", crate::ps::run(&ps)?);
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
        let ps = format!(
            "$ErrorActionPreference = 'Stop'\n{}\nWrite-Output \"Reglas AEGN retiradas; el resto de la politica local se conserva.\"",
            strip_script()
        );
        print!("{}", crate::ps::run(&ps)?);
        Ok(())
    }

    #[cfg(not(windows))]
    {
        let _ = apply;
        println!("[info] La reversion de politicas solo esta disponible en Windows.");
        Ok(())
    }
}

/// PowerShell que retira de la politica AppLocker local las reglas cuyo nombre
/// empieza por RULE_TAG y la vuelve a escribir. Las demas reglas y colecciones
/// se conservan; si la coleccion Exe se queda vacia pasa a NotConfigured.
#[cfg(windows)]
fn strip_script() -> String {
    format!(
        r#"[xml]$local = Get-AppLockerPolicy -Local -Xml
$ours = @($local.SelectNodes("//*[starts-with(@Name, '{RULE_TAG}')]"))
if ($ours.Count -gt 0) {{
  foreach ($n in $ours) {{ [void]$n.ParentNode.RemoveChild($n) }}
  foreach ($c in @($local.SelectNodes("//RuleCollection"))) {{
    if (-not $c.HasChildNodes) {{ $c.SetAttribute('EnforcementMode', 'NotConfigured') }}
  }}
  $stripped = Join-Path $env:TEMP 'aegn-applocker-local.xml'
  $local.Save($stripped)
  Set-AppLockerPolicy -XmlPolicy $stripped
  Remove-Item $stripped -Force
  Write-Output ("Retiradas " + $ours.Count + " reglas AEGN previas.")
}}"#
    )
}

/// Deja AppIDSvc (Application Identity) en arranque automatico y lo arranca.
/// Set-Service da "Access denied" con este servicio incluso como admin; sc.exe
/// suele funcionar. Si no, se avisa sin abortar: el servicio es de arranque por
/// trigger y la directiva tambien puede fijarlo via GPO.
#[cfg(windows)]
const SERVICE_PS: &str = r#"$ErrorActionPreference = 'Continue'
& sc.exe config AppIDSvc start= auto | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Output "[aviso] sc.exe no pudo poner AppIDSvc en automatico (codigo $LASTEXITCODE); configuralo por GPO." }
Start-Service -Name AppIDSvc -ErrorAction SilentlyContinue
Write-Output ("Servicio AppIDSvc: " + (Get-Service AppIDSvc).Status)
$global:LASTEXITCODE = 0"#;

#[cfg(test)]
mod tests {
    use super::*;

    fn attr<'a>(rule: &'a str, name: &str) -> &'a str {
        let start = rule.find(&format!("{name}=\"")).unwrap() + name.len() + 2;
        &rule[start..start + rule[start..].find('"').unwrap()]
    }

    fn rules(xml: &str) -> Vec<&str> {
        xml.split("<FilePathRule").skip(1).collect()
    }

    #[test]
    fn ids_son_guids_validos_y_unicos() {
        let xml = applocker_policy_xml();
        let ids: Vec<&str> = rules(&xml).iter().map(|r| attr(r, "Id")).collect();
        assert!(!ids.is_empty());
        for id in &ids {
            let parts: Vec<&str> = id.split('-').collect();
            let lens: Vec<usize> = parts.iter().map(|p| p.len()).collect();
            assert_eq!(lens, [8, 4, 4, 4, 12], "Id mal formado: {id}");
            assert!(id.chars().all(|c| c == '-' || c.is_ascii_hexdigit()), "Id no hex: {id}");
        }
        let mut unique = ids.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), ids.len(), "Ids repetidos");
    }

    #[test]
    fn todas_las_reglas_llevan_la_etiqueta() {
        // revert/enforce localizan las reglas propias por este prefijo.
        let xml = applocker_policy_xml();
        for rule in rules(&xml) {
            assert!(attr(rule, "Name").starts_with(RULE_TAG), "regla sin etiqueta: {rule}");
        }
    }

    #[test]
    fn deniega_carpetas_de_usuario_y_permite_admins() {
        let xml = applocker_policy_xml();
        let has = |path: &str, action: &str, sid: &str| {
            rules(&xml).iter().any(|r| {
                r.contains(&format!("Path=\"{path}\""))
                    && attr(r, "Action") == action
                    && attr(r, "UserOrGroupSid") == sid
            })
        };
        assert!(has(r"%OSDRIVE%\Users\*\AppData\Local\*", "Deny", "S-1-1-0"));
        assert!(has(r"%OSDRIVE%\Users\*\Downloads\*", "Deny", "S-1-1-0"));
        assert!(has("*", "Allow", "S-1-5-32-544"));
    }
}
