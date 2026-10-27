//! Rescate: deshace todo lo que puede bloquear el equipo al iniciar sesion.
//!
//! Vacia la politica AppLocker local entera (con copia previa), para AppIDSvc,
//! quita las reglas de firewall y las directivas de navegador del agente,
//! elimina la tarea `AEGN-Agent` y descarga los perfiles `HKU\AEGN_*` que
//! versiones antiguas dejaron montados. Cada paso es independiente: si uno
//! falla, los demas se ejecutan igual. El MSI lo ejecuta al instalar.

use anyhow::Result;

/// Politica AppLocker vacia: las cinco colecciones sin reglas ni aplicacion.
const EMPTY_POLICY: &str = r#"<AppLockerPolicy Version="1"><RuleCollection Type="Exe" EnforcementMode="NotConfigured" /><RuleCollection Type="Msi" EnforcementMode="NotConfigured" /><RuleCollection Type="Script" EnforcementMode="NotConfigured" /><RuleCollection Type="Dll" EnforcementMode="NotConfigured" /><RuleCollection Type="Appx" EnforcementMode="NotConfigured" /></AppLockerPolicy>"#;

fn script() -> String {
    format!(
        r#"$ErrorActionPreference = 'Continue'
$pasta = Join-Path $env:ProgramData 'AEGN'
New-Item -ItemType Directory -Force -Path $pasta | Out-Null

# 1. AppLocker: copia y politica local vacia.
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

# 2. Servicio Application Identity: manual y parado.
& sc.exe config AppIDSvc start= demand | Out-Null
& sc.exe stop AppIDSvc | Out-Null
Write-Output '  [ok] AppIDSvc em manual (fica sem efeito após reiniciar)'

# 3. Firewall del agente.
$r = @(Get-NetFirewallRule -Group 'AEGN-RemoteAccess' -ErrorAction SilentlyContinue)
$r | Remove-NetFirewallRule -ErrorAction SilentlyContinue
Write-Output ("  [ok] Regras de firewall AEGN retiradas: " + $r.Count)

# 4. Tarea pesada del agente.
Unregister-ScheduledTask -TaskName 'AEGN-Agent' -Confirm:$false -ErrorAction SilentlyContinue
Write-Output '  [ok] Tarefa AEGN-Agent removida'

# 5. Perfiles montados por versiones antiguas.
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
        println!("[simulação] Seria esvaziado o AppLocker local (com cópia), parado o AppIDSvc,");
        println!(
            "[simulação] retiradas as regras de firewall e as diretivas de navegador do AEGN,"
        );
        println!("[simulação] removida a tarefa AEGN-Agent e desmontados os perfis HKU\\AEGN_*.");
        println!("[simulação] Execute com --aplicar (consola de administrador).");
        return Ok(());
    }

    #[cfg(windows)]
    {
        print!("{}", crate::ps::run(&script())?);
        if let Err(e) = crate::browser::revert(true) {
            println!("  [erro] navegador: {e:#}");
        }
        Ok(())
    }

    #[cfg(not(windows))]
    {
        let _ = script;
        println!("[info] O resgate só está disponível no Windows.");
        Ok(())
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
}
