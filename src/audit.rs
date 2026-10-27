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
        print!("{}", crate::ps::run(ps)?);
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
///
/// En Windows el dry-run tambien busca en el registro, para mostrar que
/// programas coinciden y que comando se ejecutaria con `--apply`.
pub fn remove(name: &str, apply: bool) -> Result<()> {
    #[cfg(windows)]
    {
        if !apply {
            println!("[dry-run] Buscando software que coincida con: '{name}'");
            print!("{}", crate::ps::run(&uninstall_script(name, false))?);
            println!("[dry-run] Ejecuta con --apply para desinstalar de verdad (requiere admin).");
            return Ok(());
        }

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

        // Fallback: la UninstallString registrada por el propio instalador.
        print!("{}", crate::ps::run(&uninstall_script(name, true))?);
        Ok(())
    }

    #[cfg(not(windows))]
    {
        if !apply {
            println!("[dry-run] Se desinstalaria el software que coincida con: '{name}'");
            println!("[dry-run] Ejecuta con --apply para desinstalar de verdad (requiere admin).");
        } else {
            println!("[info] La desinstalacion solo esta disponible en Windows ('{name}').");
        }
        Ok(())
    }
}

/// Script que localiza en el registro los programas cuyo DisplayName contiene
/// `name` y, si `apply`, ejecuta su desinstalador. No encontrar nada no es un
/// error (el equipo ya esta limpio); un desinstalador que falla si lo es.
#[cfg(windows)]
fn uninstall_script(name: &str, apply: bool) -> String {
    format!(
        r#"
$name = '{name}'
$apply = ${apply}
$paths = @(
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
  'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$apps = @(Get-ItemProperty $paths -ErrorAction SilentlyContinue |
  Where-Object {{ $_.DisplayName -like "*$name*" }})
if ($apps.Count -eq 0) {{ Write-Output "NOT_FOUND: ningun programa coincide con '$name'."; exit 0 }}
$failed = $false
foreach ($app in $apps) {{
  Write-Output ("TARGET=" + $app.DisplayName + " " + $app.DisplayVersion)
  $cmd = $app.QuietUninstallString
  if (-not $cmd) {{ $cmd = $app.UninstallString }}
  if (-not $cmd) {{ Write-Output '  NO_UNINSTALL_STRING'; $failed = $true; continue }}
  # MSI registra "MsiExec.exe /I{{GUID}}", que abre el asistente de modificacion:
  # se cambia por /x silencioso.
  if ($cmd -match 'msiexec' -and $cmd -match '(\{{[0-9A-Fa-f-]{{36}}\}})') {{
    $exe = 'msiexec.exe'; $argList = "/x $($Matches[1]) /qn /norestart"
  }} else {{
    # Comillas exteriores para que cmd /c no recorte las de la ruta.
    $exe = 'cmd.exe'; $argList = '/c "' + $cmd + '"'
  }}
  Write-Output ("  CMD=" + $exe + " " + $argList)
  if (-not $apply) {{ continue }}
  $p = Start-Process -FilePath $exe -ArgumentList $argList -Wait -PassThru -NoNewWindow
  Write-Output ("  EXIT=" + $p.ExitCode)
  # 1605 = ya no estaba instalado, 3010 = OK pendiente de reinicio.
  if ($p.ExitCode -notin 0, 1605, 3010) {{ $failed = $true }}
}}
if ($failed) {{ exit 1 }}
"#,
        name = name.replace('\'', "''"),
        apply = if apply { "true" } else { "false" },
    )
}
