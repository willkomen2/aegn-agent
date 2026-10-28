//! Lista negra de programas con AppLocker.
//!
//! Todo se puede ejecutar (regla Allow "*" para Todos), excepto los programas
//! de la lista `BLOCKED`, que se niegan por editor de la firma digital: da
//! igual donde esten o como se llame el .exe. Las reglas Deny se crean para
//! cada cuenta de alumno (las que no estan en el grupo Administradores), asi
//! que a los administradores no les afecta nada, ni con UAC sin elevar.
//!
//! Antes era una lista blanca (solo Windows y Program Files) y bloqueaba cosas
//! que Windows arranca desde el perfil al iniciar sesion. Las colecciones
//! Script y Msi ya no se tocan: al retirar las reglas viejas quedan en
//! NotConfigured.
//!
//! La coleccion Appx (apps empaquetadas) lleva su propio Allow para Todos: con
//! reglas Exe en vigor y ninguna regla Appx, Windows bloquea TODAS las apps
//! empaquetadas, incluidos el menu Inicio, la busqueda y Configuracion, tambien
//! a los administradores ("o administrador bloqueou esta aplicacao").
//!
//! Los programas instalados de la lista negra los desinstala ademas
//! `auditoria limpar` (ver junk.rs); esto cubre los portables.
//!
//! Modo auditoria (`--so-auditoria`): `AuditOnly` no bloquea nada, solo registra en el visor de
//! eventos lo que se habria bloqueado (ver `events`).

use anyhow::Result;

/// Prefijo de los nombres de las reglas del agente, para distinguirlas y
/// revertirlas sin tocar otras directivas. Se conserva el de la version con
/// lista blanca para que `strip_script` tambien retire aquellas reglas.
const RULE_TAG: &str = "AEGN-Deny-UserFolders";

const EVERYONE: &str = "S-1-1-0";
#[cfg(windows)]
const ADMINS: &str = "S-1-5-32-544";

/// Programas negados a los alumnos: (nombre, editor tal como lo muestra
/// AppLocker). Los editores salen de la firma de los instaladores oficiales.
const BLOCKED: &[(&str, &str)] = &[
    ("RustDesk", "O=PURSLANE, S=NORTH WEST, C=SG"),
    (
        "AnyDesk",
        "O=ANYDESK SOFTWARE GMBH, L=STUTTGART, S=BADEN-WÜRTTEMBERG, C=DE",
    ),
    ("TeamViewer", "O=TEAMVIEWER GERMANY GMBH, L=GÖPPINGEN, C=DE"),
    (
        "Roblox",
        "O=ROBLOX CORPORATION, L=SAN MATEO, S=CALIFORNIA, C=US",
    ),
    ("Steam", "O=VALVE CORP., L=BELLEVUE, S=WASHINGTON, C=US"),
    (
        "Battle.net",
        "O=\"BLIZZARD ENTERTAINMENT, INC.\", L=IRVINE, S=CALIFORNIA, C=US",
    ),
];

/// Marca donde `enforce` mete las reglas Deny de cada cuenta de alumno.
const STUDENT_RULES: &str = "    <!-- AEGN: contas de aluno -->\n";

/// Escapa un valor para un atributo XML.
#[cfg_attr(not(windows), allow(dead_code))]
fn xml_attr(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
}

/// Regla Deny de `BLOCKED[i]`, con `__ID__`, `__SID__` y `__CONTA__` para que
/// el PowerShell ponga el GUID, el SID y el nombre de cada alumno.
#[cfg_attr(not(windows), allow(dead_code))]
fn deny_template(name: &str, publisher: &str) -> String {
    format!(
        "    <FilePublisherRule Id=\"__ID__\" Name=\"{RULE_TAG}: {name} (__CONTA__)\" \
         Description=\"AEGN Security - Escola AEGN\" UserOrGroupSid=\"__SID__\" Action=\"Deny\">\n\
         \x20     <Conditions><FilePublisherCondition PublisherName=\"{}\" ProductName=\"*\" BinaryName=\"*\">\
         <BinaryVersionRange LowSection=\"*\" HighSection=\"*\" /></FilePublisherCondition></Conditions>\n\
         \x20   </FilePublisherRule>\n",
        xml_attr(publisher)
    )
}

/// PowerShell que sustituye STUDENT_RULES en `$xml` por las reglas Deny de
/// cada alumno: cuentas locales y perfiles del equipo (dominio o Entra ID) que
/// no sean miembros directos de Administradores.
#[cfg(windows)]
fn students_script() -> String {
    let templates: Vec<String> = BLOCKED
        .iter()
        .map(|(n, p)| format!("@'\n{}'@", deny_template(n, p)))
        .collect();
    format!(
        r#"$admins = @()
try {{
  $g = Get-CimInstance Win32_Group -Filter "SID='{ADMINS}'"
  $admins = @(Get-CimAssociatedInstance -InputObject $g -Association Win32_GroupUser | ForEach-Object {{ $_.SID }})
}} catch {{ throw "não foi possível ler os membros de Administradores: $_" }}
$contas = @{{}}
Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=True' | ForEach-Object {{ $contas[$_.SID] = $_.Name }}
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' | ForEach-Object {{
  $sid = $_.PSChildName
  $dir = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).ProfileImagePath
  if ($dir -and -not $contas.ContainsKey($sid)) {{ $contas[$sid] = Split-Path -Leaf $dir }}
}}
$alunos = @($contas.Keys | Where-Object {{ $_ -match '^S-1-(5-21|12-1)-' -and $admins -notcontains $_ }} | Sort-Object)
$modelos = @(
{templates}
)
$regras = foreach ($sid in $alunos) {{
  $conta = [Security.SecurityElement]::Escape($contas[$sid])
  foreach ($m in $modelos) {{ $m.Replace('__ID__', [guid]::NewGuid().ToString()).Replace('__SID__', $sid).Replace('__CONTA__', $conta) }}
}}
$xml = $xml.Replace('{mark}', (-join $regras))
Write-Output ("Contas de aluno com a lista negra: " + (($alunos | ForEach-Object {{ $contas[$_] }}) -join ', '))"#,
        templates = templates.join(",\n"),
        mark = STUDENT_RULES.trim_end_matches('\n'),
    )
}

/// Politica AppLocker en XML: Allow "*" a Todos y el hueco de las reglas de
/// los alumnos, mas el Allow de todas las apps empaquetadas firmadas (la regla
/// por defecto de Microsoft). `audit_only` la deja en modo AuditOnly.
fn applocker_policy_xml(audit_only: bool) -> String {
    let mode = if audit_only { "AuditOnly" } else { "Enabled" };
    format!(
        "<AppLockerPolicy Version=\"1\">\n\
         \x20 <RuleCollection Type=\"Exe\" EnforcementMode=\"{mode}\">\n\
         \x20   <FilePathRule Id=\"ae6e0000-0000-4000-8000-000000000001\" Name=\"{RULE_TAG}: Permitir tudo\" \
         Description=\"AEGN Security - Escola AEGN\" UserOrGroupSid=\"{EVERYONE}\" Action=\"Allow\">\n\
         \x20     <Conditions><FilePathCondition Path=\"*\" /></Conditions>\n\
         \x20   </FilePathRule>\n\
         {STUDENT_RULES}\
         \x20 </RuleCollection>\n\
         \x20 <RuleCollection Type=\"Appx\" EnforcementMode=\"{mode}\">\n\
         \x20   <FilePublisherRule Id=\"ae6e0000-0000-4000-8000-000000000002\" Name=\"{RULE_TAG}: Apps empacotadas\" \
         Description=\"AEGN Security - Escola AEGN\" UserOrGroupSid=\"{EVERYONE}\" Action=\"Allow\">\n\
         \x20     <Conditions><FilePublisherCondition PublisherName=\"*\" ProductName=\"*\" BinaryName=\"*\">\
         <BinaryVersionRange LowSection=\"0.0.0.0\" HighSection=\"*\" /></FilePublisherCondition></Conditions>\n\
         \x20   </FilePublisherRule>\n\
         \x20 </RuleCollection>\n\
         </AppLockerPolicy>"
    )
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
  $c | ForEach-Object { "  " + $_.Action + "  " + $_.Name + "  " + (@($_.PathConditions) + @($_.PublisherConditions | ForEach-Object { $_.PublisherName }) -join ', ') }
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

/// Aplica la lista negra a las cuentas de alumno. Dry-run salvo `apply`.
/// Con `audit_only` no bloquea: solo registra eventos de lo que bloquearia.
pub fn enforce(apply: bool, audit_only: bool) -> Result<()> {
    let xml = applocker_policy_xml(audit_only);
    if audit_only {
        println!("[nota] Modo auditoria: nada é bloqueado, apenas se registam eventos (aegn politica eventos).");
    }

    if !apply {
        println!("[simulação] Seria aplicada a seguinte política AppLocker:\n");
        println!("{xml}");
        println!("\n[simulação] No lugar da marca, para cada conta de aluno, um Deny por editor:");
        for (name, publisher) in BLOCKED {
            println!("  {name}: {publisher}");
        }
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
{students}
$tmp = Join-Path $env:TEMP 'aegn-applocker.xml'
Set-Content -Path $tmp -Value $xml -Encoding UTF8
Set-AppLockerPolicy -XmlPolicy $tmp -Merge
Remove-Item $tmp -Force
Write-Output "Política AEGN aplicada e fundida com a existente."
{service}
"#,
            strip = strip_script(),
            students = students_script(),
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

/// Si las reglas del agente ya estan en la politica local, las sustituye por
/// las de esta version manteniendo el modo (AuditOnly o Enabled). Si no estan,
/// no hace nada: el bloqueo solo se activa cuando lo pide un administrador.
pub fn refresh(apply: bool) -> Result<()> {
    if !apply {
        println!("[simulação] Se as regras '{RULE_TAG}' já estiverem aplicadas, seriam substituídas pelas desta versão.");
        return Ok(());
    }

    #[cfg(windows)]
    {
        let ps = format!(
            r#"[xml]$l = Get-AppLockerPolicy -Local -Xml
$c = $l.SelectSingleNode("//RuleCollection[*[starts-with(@Name, '{RULE_TAG}')]]")
if (-not $c) {{ 'nenhuma' }} elseif ($c.EnforcementMode -eq 'AuditOnly') {{ 'auditoria' }} else {{ 'ativa' }}"#
        );
        match crate::ps::run(&ps)?.trim() {
            "nenhuma" => {
                println!("Sem regras AEGN aplicadas: nada a atualizar.");
                Ok(())
            }
            mode => enforce(true, mode == "auditoria"),
        }
    }

    #[cfg(not(windows))]
    {
        println!("[info] A atualização das políticas só está disponível no Windows.");
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

    #[test]
    fn permite_todo_a_todos() {
        let xml = applocker_policy_xml(false);
        assert!(xml.contains(&format!("UserOrGroupSid=\"{EVERYONE}\" Action=\"Allow\"")));
        assert!(xml.contains("<FilePathCondition Path=\"*\" />"));
        // Ningun Deny fijo: los Deny solo van a cuentas de alumno.
        assert!(!xml.contains("Action=\"Deny\""));
        assert_eq!(xml.matches(STUDENT_RULES).count(), 1);
    }

    #[test]
    fn solo_toca_las_colecciones_exe_y_appx() {
        for (audit, mode) in [(false, "Enabled"), (true, "AuditOnly")] {
            let xml = applocker_policy_xml(audit);
            for c in ["Exe", "Appx"] {
                assert!(xml.contains(&format!(
                    "<RuleCollection Type=\"{c}\" EnforcementMode=\"{mode}\">"
                )));
            }
            assert_eq!(xml.matches("<RuleCollection").count(), 2);
        }
    }

    #[test]
    fn las_apps_empaquetadas_se_permiten_a_todos() {
        // Sin esto, el menu Inicio y Configuracion quedan bloqueados.
        let xml = applocker_policy_xml(false);
        let appx = &xml[xml.find("Type=\"Appx\"").unwrap()..];
        assert!(appx.contains(&format!("UserOrGroupSid=\"{EVERYONE}\" Action=\"Allow\"")));
        assert!(appx.contains("PublisherName=\"*\" ProductName=\"*\" BinaryName=\"*\""));
        // Con el prefijo, strip_script tambien la retira.
        assert!(appx.contains(&format!("Name=\"{RULE_TAG}: Apps empacotadas\"")));
    }

    #[test]
    fn plantillas_deny_por_editor() {
        for (name, publisher) in BLOCKED {
            let t = deny_template(name, publisher);
            assert!(t.contains("Action=\"Deny\""));
            assert!(t.contains("UserOrGroupSid=\"__SID__\""));
            assert!(t.contains(&format!("Name=\"{RULE_TAG}: {name}")));
            assert!(!t.contains("'@"), "rompería el here-string de PowerShell");
        }
        // Las comillas del editor de Blizzard van escapadas.
        let b = deny_template("Battle.net", BLOCKED[5].1);
        assert!(b.contains("PublisherName=\"O=&quot;BLIZZARD ENTERTAINMENT, INC.&quot;,"));
    }

    #[test]
    fn marca_es_un_comentario_xml_valido() {
        let c = STUDENT_RULES.trim();
        assert!(c.starts_with("<!--") && c.ends_with("-->"));
        assert!(!c[4..c.len() - 3].contains("--"));
    }
}
