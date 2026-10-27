//! Tarea programada que reaplica el proceso de forma periodica.
//!
//! Registra la tarea `AEGN-Agent`, que corre como SYSTEM al arrancar el equipo
//! y cada dia a las 12:00 con `aegn executar --aplicar --simples`, de modo que si
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
    let mut args = String::from("executar --aplicar --simples");
    if audit_only {
        args.push_str(" --so-auditoria");
    }
    args
}

/// Instala o actualiza la tarea. Dry-run salvo `apply`.
pub fn install(apply: bool, audit_only: bool) -> Result<()> {
    let args = task_args(audit_only);
    if !apply {
        println!("[simulação] Seria registada a tarefa '{TASK}' como SYSTEM (no arranque e diariamente às 12:00):");
        println!("[simulação]   aegn {args}");
        println!("[simulação] Requisito: aegn.exe instalado dentro de Program Files.");
        println!("[simulação] Execute com --aplicar para a registar (requer administrador).");
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
Write-Output "Tarefa {TASK} registada. Registo: $log"
"#,
            exe = q(&exe),
            log = q(&log),
        );
        print!("{}", crate::ps::run(&ps)?);
        Ok(())
    }

    #[cfg(not(windows))]
    {
        println!("[info] As tarefas agendadas só estão disponíveis no Windows.");
        Ok(())
    }
}

/// Elimina la tarea. Dry-run salvo `apply`.
pub fn remove(apply: bool) -> Result<()> {
    if !apply {
        println!("[simulação] Seria eliminada a tarefa agendada '{TASK}'.");
        return Ok(());
    }

    #[cfg(windows)]
    {
        let ps = format!(
            "if (Get-ScheduledTask -TaskName '{TASK}' -ErrorAction SilentlyContinue) {{\n\
             Unregister-ScheduledTask -TaskName '{TASK}' -Confirm:$false\n\
             Write-Output 'Tarefa {TASK} eliminada.' }} else {{ Write-Output 'A tarefa {TASK} não existe.' }}"
        );
        print!("{}", crate::ps::run(&ps)?);
        Ok(())
    }

    #[cfg(not(windows))]
    {
        println!("[info] As tarefas agendadas só estão disponíveis no Windows.");
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
if (-not $t) {{ Write-Output 'Tarefa {TASK} não instalada.'; exit 0 }}
$i = $t | Get-ScheduledTaskInfo
Write-Output ("Tarefa {TASK}: " + $t.State)
Write-Output ("  Última execução: " + $i.LastRunTime + "  resultado: " + $i.LastTaskResult)
Write-Output ("  Próxima: " + $i.NextRunTime)
Write-Output ("  Ação: " + $t.Actions[0].Arguments)
if (Test-Path '{log}') {{ Write-Output '--- Últimas linhas do registo ---'; Get-Content '{log}' -Tail 20 }}
"#
        );
        print!("{}", crate::ps::run(&ps)?);
        Ok(())
    }

    #[cfg(not(windows))]
    {
        println!("[info] As tarefas agendadas só estão disponíveis no Windows.");
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
            "O aegn.exe está em '{plain}'. Para instalar a tarefa, instale-o primeiro em Program Files \
             (ex.: C:\\Program Files\\AEGN\\aegn.exe): uma tarefa SYSTEM não deve lançar um \
             executável que um utilizador consiga substituir."
        );
    }
    Ok(std::path::PathBuf::from(plain))
}

#[cfg(test)]
mod tests {
    #[test]
    fn la_tarea_respeta_el_modo_auditoria() {
        assert_eq!(super::task_args(false), "executar --aplicar --simples");
        assert_eq!(
            super::task_args(true),
            "executar --aplicar --simples --so-auditoria"
        );
    }
}
