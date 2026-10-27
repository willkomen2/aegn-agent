//! Politicas de restriccion de ejecucion en carpetas de usuario.
//!
//! El objetivo es impedir que se ejecuten binarios, scripts o instaladores
//! arbitrarios desde rutas escribibles por el usuario (donde no hace falta ser
//! administrador para copiar archivos), que es el bypass tipico para correr
//! instaladores, juegos o herramientas de acceso remoto portables.
//!
//! Mecanismo: reglas de ruta de AppLocker (`Set-AppLockerPolicy`), el metodo
//! soportado por Microsoft para control de aplicaciones. Es transparente y
//! reversible: queda registrado en la directiva y se puede auditar.
//!
//! Colecciones: Exe, Script (.ps1 .bat .cmd .vbs .js) y Msi. En cada una solo
//! se permite %WINDIR% y %PROGRAMFILES% (MSI: %WINDIR%\Installer) a todos y
//! cualquier ruta a los administradores; lo demas queda bloqueado por defecto.
//! AppData\Local y Downloads llevan ademas un Deny explicito en Exe.
//!
//! Modo auditoria (`--so-auditoria`): `AuditOnly` no bloquea nada, solo registra en el visor de
//! eventos lo que se habria bloqueado (ver `events`). Es el paso previo
//! recomendado antes de activar el bloqueo en un aula.

use anyhow::Result;

/// Identificador de grupo que el agente usa en sus reglas, para poder
/// distinguirlas y revertirlas sin tocar otras directivas existentes.
const RULE_TAG: &str = "AEGN-Deny-UserFolders";

const EVERYONE: &str = "S-1-1-0";
const ADMINS: &str = "S-1-5-32-544";

/// Una regla de ruta: (coleccion, nombre, sid, accion, ruta).
type Rule = (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
);

/// Reglas del agente. Las de Allow son las reglas por defecto de AppLocker:
/// con una coleccion activa, lo que no case con ningun Allow queda bloqueado.
/// Los Deny tienen prioridad sobre los Allow y aplican tambien a los admins.
const RULES: &[Rule] = &[
    (
        "Exe",
        "AppData Local",
        EVERYONE,
        "Deny",
        r"%OSDRIVE%\Users\*\AppData\Local\*",
    ),
    (
        "Exe",
        "Transferências",
        EVERYONE,
        "Deny",
        r"%OSDRIVE%\Users\*\Downloads\*",
    ),
    (
        "Exe",
        "Permitir Program Files",
        EVERYONE,
        "Allow",
        r"%PROGRAMFILES%\*",
    ),
    ("Exe", "Permitir Windows", EVERYONE, "Allow", r"%WINDIR%\*"),
    ("Exe", "Permitir Administradores", ADMINS, "Allow", "*"),
    (
        "Script",
        "Scripts em Program Files",
        EVERYONE,
        "Allow",
        r"%PROGRAMFILES%\*",
    ),
    (
        "Script",
        "Scripts do Windows",
        EVERYONE,
        "Allow",
        r"%WINDIR%\*",
    ),
    (
        "Script",
        "Scripts dos Administradores",
        ADMINS,
        "Allow",
        "*",
    ),
    (
        "Msi",
        "Instaladores do Windows",
        EVERYONE,
        "Allow",
        r"%WINDIR%\Installer\*",
    ),
    ("Msi", "MSI dos Administradores", ADMINS, "Allow", "*"),
];

/// Politica AppLocker en XML. `audit_only` la deja en modo AuditOnly.
fn applocker_policy_xml(audit_only: bool) -> String {
    let mode = if audit_only { "AuditOnly" } else { "Enabled" };
    let mut xml = String::from("<AppLockerPolicy Version=\"1\">\n");
    for collection in ["Exe", "Script", "Msi"] {
        xml.push_str(&format!(
            "  <RuleCollection Type=\"{collection}\" EnforcementMode=\"{mode}\">\n"
        ));
        for (i, (_, name, sid, action, path)) in
            RULES.iter().enumerate().filter(|(_, r)| r.0 == collection)
        {
            xml.push_str(&format!(
                "    <FilePathRule Id=\"ae6e0000-0000-4000-8000-0000000000{:02x}\" Name=\"{RULE_TAG}: {name}\" \
                 Description=\"AEGN Security - Escola AEGN\" UserOrGroupSid=\"{sid}\" Action=\"{action}\">\n\
                 \x20     <Conditions><FilePathCondition Path=\"{path}\" /></Conditions>\n\
                 \x20   </FilePathRule>\n",
                i + 1
            ));
        }
        xml.push_str("  </RuleCollection>\n");
    }
    xml.push_str("</AppLockerPolicy>");
    xml
}

/// Muestra el estado actual de las politicas de restriccion.
pub fn status() -> Result<()> {
    #[cfg(windows)]
    {
        let ps = r#"
$svc = Get-Service AppIDSvc -ErrorAction SilentlyContinue
if ($svc) { Write-Output ("Serviço AppIDSvc (AppLocker): " + $svc.Status) }
else { Write-Output "Serviço AppIDSvc não encontrado." }
foreach ($c in (Get-AppLockerPolicy -Effective).RuleCollections) {
  Write-Output ("--- " + $c.RuleCollectionType + ": " + $c.EnforcementMode + " ---")
  $c | ForEach-Object { "  " + $_.Action + "  " + $_.Name + "  " + ($_.PathConditions -join ', ') }
}
"#;
        print!("{}", crate::ps::run(ps)?);
        Ok(())
    }

    #[cfg(not(windows))]
    {
        println!("[info] O estado das políticas só está disponível no Windows.");
        println!("[info] Consultaria Get-AppLockerPolicy -Effective e o serviço AppIDSvc.");
        Ok(())
    }
}

/// Aplica el bloqueo de ejecucion en carpetas de usuario. Dry-run salvo `apply`.
/// Con `audit_only` no bloquea: solo registra eventos de lo que bloquearia.
pub fn enforce(apply: bool, audit_only: bool) -> Result<()> {
    let xml = applocker_policy_xml(audit_only);
    if audit_only {
        println!("[nota] Modo auditoria: nada é bloqueado, apenas se registam eventos (aegn politica eventos).");
    }

    if !apply {
        println!("[simulação] Seria aplicada a seguinte política AppLocker:\n");
        println!("{xml}");
        println!("\n[simulação] Execute com --aplicar para a aplicar (requer administrador).");
        println!("[nota] O serviço Application Identity (AppIDSvc) tem de estar em execução.");
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
Write-Output "Política AEGN aplicada e fundida com a existente."
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
        println!("[info] A aplicação de políticas só está disponível no Windows.");
        Ok(())
    }
}

/// Revierte las reglas aplicadas por el agente (identificadas por RULE_TAG).
pub fn revert(apply: bool) -> Result<()> {
    if !apply {
        println!("[simulação] Seriam eliminadas as regras AppLocker com a etiqueta '{RULE_TAG}'.");
        println!(
            "[simulação] Execute com --aplicar para reverter de facto (requer administrador)."
        );
        return Ok(());
    }

    #[cfg(windows)]
    {
        let ps = format!(
            "$ErrorActionPreference = 'Stop'\n{}\nWrite-Output \"Regras AEGN retiradas; o resto da política local mantém-se.\"",
            strip_script()
        );
        print!("{}", crate::ps::run(&ps)?);
        Ok(())
    }

    #[cfg(not(windows))]
    {
        let _ = apply;
        println!("[info] A reversão das políticas só está disponível no Windows.");
        Ok(())
    }
}

/// Muestra los ultimos eventos de AppLocker: bloqueos (8004, 8007, 8022) y lo
/// que se habria bloqueado en modo auditoria (8003, 8006, 8021).
pub fn events(max: u32) -> Result<()> {
    #[cfg(windows)]
    {
        let ps = format!(
            r#"
$logs = 'Microsoft-Windows-AppLocker/EXE and DLL', 'Microsoft-Windows-AppLocker/MSI and Script'
$ev = Get-WinEvent -FilterHashtable @{{ LogName = $logs; Id = 8003, 8004, 8006, 8007, 8021, 8022 }} -MaxEvents {max} -ErrorAction SilentlyContinue
if (-not $ev) {{ Write-Output 'Sem eventos do AppLocker registados.'; exit 0 }}
foreach ($e in $ev) {{
  $kind = if ($e.Id -in 8003, 8006, 8021) {{ 'AUDIT' }} else {{ 'BLOQ ' }}
  $user = try {{ $e.UserId.Translate([Security.Principal.NTAccount]).Value }} catch {{ "$($e.UserId)" }}
  $msg = ($e.Message -split "`r?`n")[0]
  Write-Output ("{{0:yyyy-MM-dd HH:mm}}  {{1}}  {{2}}  {{3}}" -f $e.TimeCreated, $kind, $user, $msg)
}}
"#
        );
        print!("{}", crate::ps::run(&ps)?);
        Ok(())
    }

    #[cfg(not(windows))]
    {
        println!("[info] Os eventos do AppLocker só estão disponíveis no Windows.");
        println!(
            "[info] Leria os últimos {max} eventos 8003/8004/8006/8007 do Visualizador de Eventos."
        );
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
  Write-Output ("Retiradas " + $ours.Count + " regras AEGN anteriores.")
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
if ($LASTEXITCODE -ne 0) { Write-Output "[aviso] O sc.exe não conseguiu pôr o AppIDSvc em automático (código $LASTEXITCODE); configure-o por GPO." }
Start-Service -Name AppIDSvc -ErrorAction SilentlyContinue
Write-Output ("Serviço AppIDSvc: " + (Get-Service AppIDSvc).Status)
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
        let xml = applocker_policy_xml(false);
        let ids: Vec<&str> = rules(&xml).iter().map(|r| attr(r, "Id")).collect();
        assert!(!ids.is_empty());
        for id in &ids {
            let parts: Vec<&str> = id.split('-').collect();
            let lens: Vec<usize> = parts.iter().map(|p| p.len()).collect();
            assert_eq!(lens, [8, 4, 4, 4, 12], "Id mal formado: {id}");
            assert!(
                id.chars().all(|c| c == '-' || c.is_ascii_hexdigit()),
                "Id no hex: {id}"
            );
        }
        let mut unique = ids.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), ids.len(), "Ids repetidos");
    }

    #[test]
    fn todas_las_reglas_llevan_la_etiqueta() {
        // revert/enforce localizan las reglas propias por este prefijo.
        let xml = applocker_policy_xml(false);
        for rule in rules(&xml) {
            assert!(
                attr(rule, "Name").starts_with(RULE_TAG),
                "regla sin etiqueta: {rule}"
            );
        }
    }

    #[test]
    fn deniega_carpetas_de_usuario_y_permite_admins() {
        let xml = applocker_policy_xml(false);
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

    #[test]
    fn colecciones_y_modo() {
        for (audit, mode) in [(false, "Enabled"), (true, "AuditOnly")] {
            let xml = applocker_policy_xml(audit);
            for c in ["Exe", "Script", "Msi"] {
                let tag = format!("<RuleCollection Type=\"{c}\" EnforcementMode=\"{mode}\">");
                assert!(xml.contains(&tag), "falta {tag}");
            }
        }
    }
}
