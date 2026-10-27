//! Tarea programada que reaplica el proceso de forma periodica.
//!
//! Registra la tarea `AEGN-Agent`, que corre como SYSTEM al arrancar el equipo
//! y cada dia a las 12:00 con `aegn run --apply --simple`, de modo que si
//! alguien reinstala RustDesk o retira una regla, el equipo vuelve solo a su
//! estado correcto. La salida se anade a `logs\aegn.log` junto al ejecutable.
//!
//! Seguridad: una tarea SYSTEM que lanza un ejecutable que un usuario pueda
//! sustituir seria una escalada de privilegios. Por eso solo se instala si
//! `aegn.exe` esta dentro de Program Files, donde solo escriben los admins.

use anyhow::Result;

const TASK: &str = "AEGN-Agent";

/// Argumentos con los que la tarea ejecuta el agente.
fn task_args(audit_only: bool) -> String {
    let mut args = String::from("run --apply --simple");
    if audit_only {
        args.push_str(" --audit-only");
    }
    args
}

/// Instala o actualiza la tarea. Dry-run salvo `apply`.
pub fn install(apply: bool, audit_only: bool) -> Result<()> {
    let args = task_args(audit_only);
    if !apply {
        println!("[dry-run] Se registraria la tarea '{TASK}' como SYSTEM (al arrancar y diaria a las 12:00):");
        println!("[dry-run]   aegn {args}");
        println!("[dry-run] Requisito: aegn.exe instalado dentro de Program Files.");
        println!("[dry-run] Ejecuta con --apply para registrarla (requiere admin).");
        return Ok(());
    }

    #[cfg(windows)]
    {
        let exe = protected_exe()?;
        let dir = exe.parent().expect("el ejecutable tiene carpeta");
        let log = dir.join("logs").join("aegn.log");
        let q = |p: &std::path::Path| p.display().to_string().replace('\'', "''");
        let ps = format!(
            r#"
$ErrorActionPreference = 'Stop'
$exe = '{exe}'
$log = '{log}'
New-Item -ItemType Directory -Force -Path (Split-Path $log) | Out-Null
$arg = '/c ""' + $exe + '" {args} >> "' + $log + '" 2>&1"'
$action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument $arg
$triggers = @((New-ScheduledTaskTrigger -AtStartup), (New-ScheduledTaskTrigger -Daily -At '12:00'))
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 1)
Register-ScheduledTask -TaskName '{TASK}' -Action $action -Trigger $triggers -Principal $principal -Settings $settings -Force | Out-Null
Write-Output "Tarea {TASK} registrada. Log: $log"
"#,
            exe = q(&exe),
            log = q(&log),
        );
        print!("{}", crate::ps::run(&ps)?);
        Ok(())
    }

    #[cfg(not(windows))]
    {
        println!("[info] Las tareas programadas solo estan disponibles en Windows.");
        Ok(())
    }
}

/// Elimina la tarea. Dry-run salvo `apply`.
pub fn remove(apply: bool) -> Result<()> {
    if !apply {
        println!("[dry-run] Se eliminaria la tarea programada '{TASK}'.");
        return Ok(());
    }

    #[cfg(windows)]
    {
        let ps = format!(
            "if (Get-ScheduledTask -TaskName '{TASK}' -ErrorAction SilentlyContinue) {{\n\
             Unregister-ScheduledTask -TaskName '{TASK}' -Confirm:$false\n\
             Write-Output 'Tarea {TASK} eliminada.' }} else {{ Write-Output 'La tarea {TASK} no existe.' }}"
        );
        print!("{}", crate::ps::run(&ps)?);
        Ok(())
    }

    #[cfg(not(windows))]
    {
        println!("[info] Las tareas programadas solo estan disponibles en Windows.");
        Ok(())
    }
}

/// Estado de la tarea y ultimas lineas del log.
pub fn status() -> Result<()> {
    #[cfg(windows)]
    {
        let log = std::env::current_exe()?
            .parent()
            .map(|d| d.join("logs").join("aegn.log").display().to_string())
            .unwrap_or_default()
            .replace('\'', "''");
        let ps = format!(
            r#"
$t = Get-ScheduledTask -TaskName '{TASK}' -ErrorAction SilentlyContinue
if (-not $t) {{ Write-Output 'Tarea {TASK} no instalada.'; exit 0 }}
$i = $t | Get-ScheduledTaskInfo
Write-Output ("Tarea {TASK}: " + $t.State)
Write-Output ("  Ultima ejecucion: " + $i.LastRunTime + "  resultado: " + $i.LastTaskResult)
Write-Output ("  Proxima: " + $i.NextRunTime)
Write-Output ("  Accion: " + $t.Actions[0].Arguments)
if (Test-Path '{log}') {{ Write-Output '--- Ultimas lineas del log ---'; Get-Content '{log}' -Tail 20 }}
"#
        );
        print!("{}", crate::ps::run(&ps)?);
        Ok(())
    }

    #[cfg(not(windows))]
    {
        println!("[info] Las tareas programadas solo estan disponibles en Windows.");
        Ok(())
    }
}

/// Ruta real del ejecutable, exigiendo que este bajo Program Files.
#[cfg(windows)]
fn protected_exe() -> Result<std::path::PathBuf> {
    let exe = std::fs::canonicalize(std::env::current_exe()?)?;
    let plain = exe.display().to_string();
    let plain = plain.strip_prefix(r"\\?\").unwrap_or(&plain).to_string();
    let roots: Vec<String> = ["ProgramFiles", "ProgramW6432", "ProgramFiles(x86)"]
        .iter()
        .filter_map(|v| std::env::var(v).ok())
        .map(|r| format!("{}\\", r.trim_end_matches('\\').to_lowercase()))
        .collect();
    if !roots.iter().any(|r| plain.to_lowercase().starts_with(r)) {
        anyhow::bail!(
            "aegn.exe esta en '{plain}'. Para instalar la tarea copialo antes a Program Files \
             (p. ej. C:\\Program Files\\aegn\\aegn.exe): una tarea SYSTEM no debe lanzar un \
             ejecutable que un usuario pueda sustituir."
        );
    }
    Ok(std::path::PathBuf::from(plain))
}

#[cfg(test)]
mod tests {
    #[test]
    fn la_tarea_respeta_el_modo_auditoria() {
        assert_eq!(super::task_args(false), "run --apply --simple");
        assert_eq!(super::task_args(true), "run --apply --simple --audit-only");
    }
}
