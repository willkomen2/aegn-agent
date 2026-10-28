//! Diagnostico: informe corto del estado del equipo y envio a ntfy.sh.
//!
//! Sirve para ver desde fuera si un PC sigue bloqueado al iniciar sesion sin
//! tener que ir a mirarlo. El informe dice la version, el AppLocker efectivo y
//! su cache, AppIDSvc, los bloqueos de AppLocker de las ultimas 48 h, si hay
//! algo que oculte Encerrar/Reiniciar (power.rs en simulacion) y el final del
//! registro del rescate.
//!
//! ntfy.sh es gratuito y sin cuenta, pero el tema es publico: quien conozca
//! el nombre lee los informes. Por eso no van nombres de cuentas: las rutas
//! `C:\Users\<nombre>` salen como `C:\Users\*` y los SIDs se tapan. Solo va el
//! nombre del equipo. ntfy.sh guarda los mensajes unas 12 horas.
//!
//! Ver los informes: https://ntfy.sh/aegn-diag-ymerk6h31cdvjl (o la app ntfy
//! suscrita a ese tema).

use anyhow::Result;

/// Tema de ntfy.sh donde se publican los informes.
const TOPIC: &str = "aegn-diag-ymerk6h31cdvjl";

const SCRIPT: &str = r#"$ErrorActionPreference = 'SilentlyContinue'
$r = New-Object Collections.Generic.List[string]
$problema = $false
$os = Get-CimInstance Win32_OperatingSystem
$r.Add(('AEGN __VER__ | ' + $env:COMPUTERNAME + ' | ' + $os.Caption + ' ' + $os.Version))
$r.Add(('Arranque: ' + $os.LastBootUpTime.ToString('yyyy-MM-dd HH:mm') + ' | agora: ' + (Get-Date -Format 'yyyy-MM-dd HH:mm')))
$s = Get-CimInstance Win32_Service -Filter "Name='AppIDSvc'"
$r.Add(('AppIDSvc: ' + $s.State + ' / ' + $s.StartMode))

try {
  $ef = [xml](Get-AppLockerPolicy -Effective -Xml -ErrorAction Stop)
  $cols = @($ef.SelectNodes('//RuleCollection'))
  if ($cols.Count -eq 0) { $r.Add('AppLocker efetivo: vazio') }
  foreach ($c in $cols) {
    $n = @($c.ChildNodes | Where-Object { $_.NodeType -eq 'Element' }).Count
    $r.Add(('AppLocker ' + $c.Type + ': ' + $c.EnforcementMode + ', ' + $n + ' regras'))
  }
} catch { $r.Add("AppLocker: erro $_") }
$cache = @(Get-ChildItem (Join-Path $env:SystemRoot 'System32\AppLocker') -File)
$r.Add(('Cache AppLocker: ' + (($cache | ForEach-Object { $_.Name + ' ' + $_.Length + 'B' }) -join ', ')))
$r.Add(('Sessao: explorer ' + @(Get-Process explorer).Count + ', menu Iniciar ' + @(Get-Process StartMenuExperienceHost).Count))

# Bloqueos (no auditoria): 8004 exe, 8007 script, 8022/8024/8025 apps empaquetadas.
$logs = 'Microsoft-Windows-AppLocker/EXE and DLL', 'Microsoft-Windows-AppLocker/MSI and Script', 'Microsoft-Windows-AppLocker/Packaged app-Execution'
$ev = @(Get-WinEvent -FilterHashtable @{ LogName = $logs; Id = 8004, 8007, 8022, 8024, 8025; StartTime = (Get-Date).AddDays(-2) } -MaxEvents 200)
$r.Add(('Bloqueios AppLocker (48h): ' + $ev.Count))
if ($ev.Count -gt 0) { $problema = $true }
foreach ($e in ($ev | Select-Object -First 6)) {
  $r.Add(('  ' + $e.TimeCreated.ToString('MM-dd HH:mm') + ' ' + $e.Id + ' ' + (($e.Message -split "`r?`n")[0])))
}

$r.Add('Energia:')
$energia = @'
__POWER__
'@
foreach ($x in @($energia -split "`r?`n" | Where-Object { $_.Trim() })) {
  $r.Add($x)
  if ($x -match 'corrigir') { $problema = $true }
}

$log = Join-Path $env:ProgramData 'AEGN\desbloquear.log'
if (Test-Path $log) {
  $r.Add('Ultimo resgate:')
  Get-Content $log -Tail 12 | ForEach-Object { $r.Add($_) }
}

# Sin nombres de cuentas: el tema de ntfy.sh es publico.
$txt = ($r -join "`n") -replace '(?i)(\\Users\\)[^\\\r\n]+', '$1*' -replace 'S-1-(5-21|12-1)-[\d-]+', 'S-1-$1-*'
if ($txt.Length -gt 3800) { $txt = $txt.Substring(0, 3800) + "`n[...]" }
Write-Output $txt

if ($send) {
  [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
  $tag = 'white_check_mark'
  if ($problema) { $tag = 'warning' }
  $h = @{ Title = ('AEGN ' + $env:COMPUTERNAME + ' __VER__'); Tags = $tag }
  if ($problema) { $h.Priority = '4' }
  try {
    Invoke-RestMethod -Uri 'https://ntfy.sh/__TOPIC__' -Method Post -Body ([Text.Encoding]::UTF8.GetBytes($txt)) -Headers $h -TimeoutSec 20 | Out-Null
    Write-Output '[ok] Diagnóstico enviado.'
  } catch { Write-Output "[erro] Envio falhou: $_" }
}
$global:LASTEXITCODE = 0"#;

/// Script con la version, el tema, `send` y la salida de power.rs.
fn script(energia: &str, send: bool) -> String {
    format!(
        "$send = {}\n{}",
        if send { "$true" } else { "$false" },
        SCRIPT
            .replace("__VER__", env!("CARGO_PKG_VERSION"))
            .replace("__TOPIC__", TOPIC)
            // Una linea "'@" cerraria el here-string antes de tiempo.
            .replace("__POWER__", &energia.replace("'@", "' @"))
    )
}

/// Muestra el diagnostico y, con `send`, lo publica en ntfy.sh.
pub fn run(send: bool) -> Result<()> {
    #[cfg(windows)]
    {
        let energia = crate::ps::run(&crate::power::script(false))
            .unwrap_or_else(|e| format!("  [erro] energia: {e:#}"));
        print!("{}", crate::ps::run(&script(&energia, send))?);
        if !send {
            println!("[info] Com --enviar publica-se em https://ntfy.sh/{TOPIC}");
        }
        Ok(())
    }

    #[cfg(not(windows))]
    {
        let _ = (script, send);
        println!("[info] O diagnóstico só está disponível no Windows.");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn el_script_no_lleva_comillas_sin_cerrar() {
        for line in script("  [ok] nada", true).lines() {
            // Las dos lineas del here-string llevan una sola comilla.
            if line.ends_with("@'") || line == "'@" {
                continue;
            }
            assert_eq!(line.matches('\'').count() % 2, 0, "{line}");
        }
    }

    #[test]
    fn la_salida_de_energia_no_cierra_el_here_string() {
        let s = script("'@\nWrite-Output hola", false);
        assert_eq!(s.lines().filter(|l| *l == "'@").count(), 1);
        assert!(s.starts_with("$send = $false\n"));
    }

    #[test]
    fn rellena_version_y_tema_y_tapa_las_cuentas() {
        let s = script("", true);
        assert!(!s.contains("__VER__") && !s.contains("__TOPIC__") && !s.contains("__POWER__"));
        assert!(s.contains(&format!("https://ntfy.sh/{TOPIC}")));
        assert!(s.contains(r"(\\Users\\)[^\\\r\n]+"));
        assert!(s.contains("S-1-(5-21|12-1)-"));
    }
}
