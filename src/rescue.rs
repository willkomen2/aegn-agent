//! Rescate: deshace todo lo que puede bloquear el equipo al iniciar sesion.
//!
//! Vacia la politica AppLocker local entera (con copia previa), para AppIDSvc,
//! quita las reglas de firewall y las directivas de navegador del agente,
//! elimina la tarea `AEGN-Agent`, repone los botones de energia (power.rs) y
//! descarga los perfiles `HKU\AEGN_*` que
//! versiones antiguas dejaron montados. Cada paso es independiente: si uno
//! falla, los demas se ejecutan igual. El MSI lo ejecuta al instalar.
//!
//! El orden de AppLocker importa (lo documenta Microsoft): AppIDSvc tiene que
//! estar en marcha mientras se aplica la politica vacia. Si se para antes, el
//! driver sigue aplicando las reglas guardadas en `System32\AppLocker\*.AppLocker`
//! y el menu Inicio sigue bloqueado. Por eso se arranca el servicio, se aplica
//! la politica, se espera, se borra esa cache y solo entonces se para.
//!
//! La salida se guarda en `%ProgramData%\AEGN\desbloquear.log`: el MSI la
//! descarta y sin registro no se sabe si el rescate funciono.

use anyhow::Result;

/// Politica AppLocker vacia: las cinco colecciones sin reglas ni aplicacion.
const EMPTY_POLICY: &str = r#"<AppLockerPolicy Version="1"><RuleCollection Type="Exe" EnforcementMode="NotConfigured" /><RuleCollection Type="Msi" EnforcementMode="NotConfigured" /><RuleCollection Type="Script" EnforcementMode="NotConfigured" /><RuleCollection Type="Dll" EnforcementMode="NotConfigured" /><RuleCollection Type="Appx" EnforcementMode="NotConfigured" /></AppLockerPolicy>"#;

fn script() -> String {
    format!(
        r#"$ErrorActionPreference = 'Continue'
$pasta = Join-Path $env:ProgramData 'AEGN'
New-Item -ItemType Directory -Force -Path $pasta | Out-Null
Write-Output ('== Resgate AEGN ' + (Get-Date -Format 's'))

# 1. AppLocker: con AppIDSvc en marcha, copia y politica local vacia.
& sc.exe start AppIDSvc | Out-Null
try {{
  $copia = Join-Path $pasta ('applocker-copia-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.xml')
  Get-AppLockerPolicy -Local -Xml | Set-Content -Path $copia -Encoding UTF8
  $vazio = Join-Path $env:TEMP 'aegn-applocker-vazio.xml'
  Set-Content -Path $vazio -Value '{EMPTY_POLICY}' -Encoding UTF8
  Set-AppLockerPolicy -XmlPolicy $vazio -ErrorAction Stop
  Remove-Item $vazio -Force
  Write-Output "  [ok] AppLocker local vazio (cópia em $copia)"
}} catch {{ Write-Output "  [erro] AppLocker: $_" }}
$ef = [xml](Get-AppLockerPolicy -Effective -Xml)
if ($ef.SelectNodes('//RuleCollection/*').Count -gt 0) {{
  Write-Output '  [aviso] Ainda há regras AppLocker vindas de uma GPO de domínio: retire-as na GPO.'
}}

# 2. Tiempo para que AppIDSvc pase la politica vacia al driver; despues se
# borra la cache, que es lo que el driver aplica si el servicio no la renueva.
Start-Sleep -Seconds 10
$cache = Join-Path $env:SystemRoot 'System32\AppLocker'
$ficheiros = @(Get-ChildItem -Path $cache -Filter '*.AppLocker' -File -ErrorAction SilentlyContinue)
$falhou = 0
foreach ($f in $ficheiros) {{
  try {{ Remove-Item -LiteralPath $f.FullName -Force -ErrorAction Stop }} catch {{ $falhou++; Write-Output "  [erro] Cache AppLocker: $($f.Name): $_" }}
}}
Write-Output ('  [ok] Cache AppLocker apagada: ' + ($ficheiros.Count - $falhou) + ' de ' + $ficheiros.Count + ' ficheiros')

# 3. Servicio Application Identity: manual y parado, ya sin reglas.
& sc.exe config AppIDSvc start= demand | Out-Null
& sc.exe stop AppIDSvc | Out-Null
Write-Output '  [ok] AppIDSvc em manual e parado'

# 4. Menu Iniciar, pesquisa y teclado tactil son apps empaquetadas: si se
# lanzaron bloqueadas, se cierran para que el Windows las vuelva a abrir ya
# sin AppLocker, sin tener que reiniciar.
$shell = @(Get-Process -Name StartMenuExperienceHost, ShellExperienceHost, SearchHost, SearchApp, TextInputHost -ErrorAction SilentlyContinue)
$shell | Stop-Process -Force -ErrorAction SilentlyContinue
Write-Output ('  [ok] Menu Iniciar e pesquisa reiniciados: ' + $shell.Count + ' processos')

# 5. Firewall del agente.
$r = @(Get-NetFirewallRule -Group 'AEGN-RemoteAccess' -ErrorAction SilentlyContinue)
$r | Remove-NetFirewallRule -ErrorAction SilentlyContinue
Write-Output ("  [ok] Regras de firewall AEGN retiradas: " + $r.Count)

# 6. Tarea pesada del agente.
Unregister-ScheduledTask -TaskName 'AEGN-Agent' -Confirm:$false -ErrorAction SilentlyContinue
Write-Output '  [ok] Tarefa AEGN-Agent removida'

# 7. Perfiles montados por versiones antiguas.
[gc]::Collect(); [gc]::WaitForPendingFinalizers()
foreach ($h in @(Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | Where-Object {{ $_.PSChildName -like 'AEGN_*' }})) {{
  $n = $h.PSChildName
  for ($i = 0; $i -lt 5; $i++) {{
    & reg.exe unload "HKU\$n" 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {{ break }}
    Start-Sleep -Seconds 2
  }}
  if ($LASTEXITCODE -eq 0) {{ Write-Output "  [ok] Perfil $n desmontado" }} else {{ Write-Output "  [erro] Perfil $n continua montado" }}
}}

if (Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers') {{
  Write-Output '  [aviso] Existem Software Restriction Policies (não são do AEGN); reveja-as em secpol.msc.'
}}
Write-Output 'Rescate concluído. Reinicie o computador.'
"#
    )
}

/// Ejecuta el rescate. Dry-run salvo `apply`.
pub fn run(apply: bool) -> Result<()> {
    if !apply {
        println!("[simulação] Seria esvaziado o AppLocker local (com cópia) e a sua cache, parado o AppIDSvc,");
        println!(
            "[simulação] retiradas as regras de firewall e as diretivas de navegador do AEGN,"
        );
        println!("[simulação] removida a tarefa AEGN-Agent e desmontados os perfis HKU\\AEGN_*,");
        println!("[simulação] e repostos os botões Encerrar e Reiniciar (aegn energia).");
        println!("[simulação] Execute com --aplicar (consola de administrador).");
        return Ok(());
    }

    #[cfg(windows)]
    {
        let res = crate::ps::run(&script());
        match &res {
            Ok(out) => {
                print!("{out}");
                save_log(out);
            }
            Err(e) => save_log(&format!("  [erro] resgate: {e:#}\n")),
        }
        if let Err(e) = crate::browser::revert(true) {
            println!("  [erro] navegador: {e:#}");
            save_log(&format!("  [erro] navegador: {e:#}\n"));
        }
        let energia = match crate::power::restore() {
            Ok(out) => out,
            Err(e) => format!("  [erro] energia: {e:#}\n"),
        };
        print!("{energia}");
        save_log(&energia);
        res.map(|_| ())
    }

    #[cfg(not(windows))]
    {
        let _ = script;
        println!("[info] O resgate só está disponível no Windows.");
        Ok(())
    }
}

/// Anade `text` a `%ProgramData%\AEGN\desbloquear.log`. Si no se puede
/// escribir, se sigue: el registro no debe impedir el rescate.
#[cfg(windows)]
fn save_log(text: &str) {
    use std::io::Write;
    let Some(base) = std::env::var_os("ProgramData") else {
        return;
    };
    let dir = std::path::Path::new(&base).join("AEGN");
    let _ = std::fs::create_dir_all(&dir);
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("desbloquear.log"))
    {
        let _ = f.write_all(text.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn politica_vacia_con_las_cinco_colecciones() {
        for c in ["Exe", "Msi", "Script", "Dll", "Appx"] {
            assert!(
                EMPTY_POLICY.contains(&format!("Type=\"{c}\" EnforcementMode=\"NotConfigured\""))
            );
        }
        assert!(!EMPTY_POLICY.contains('\''));
    }

    #[test]
    fn el_script_no_lleva_comillas_sin_cerrar() {
        for line in script().lines() {
            assert_eq!(line.matches('\'').count() % 2, 0, "{line}");
        }
    }

    #[test]
    fn appidsvc_se_para_despues_de_vaciar_la_politica_y_la_cache() {
        let s = script();
        let pos = |t: &str| s.find(t).unwrap_or_else(|| panic!("falta: {t}"));
        let arranca = pos("sc.exe start AppIDSvc");
        let politica = pos("Set-AppLockerPolicy -XmlPolicy $vazio");
        let cache = pos("System32\\AppLocker");
        let para = pos("sc.exe stop AppIDSvc");
        assert!(arranca < politica && politica < cache && cache < para);
    }
}
