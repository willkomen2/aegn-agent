//! Sesiones del navegador: al cerrar la sesion de Windows no queda ninguna
//! cuenta de Google (ni de otro sitio) abierta para el siguiente alumno.
//!
//! Se hace con las directivas oficiales de cada navegador en
//! `HKLM\SOFTWARE\Policies`, que el usuario no puede cambiar:
//! - Chrome: `ClearBrowsingDataOnExitList` borra cookies y contraseñas al
//!   cerrar el navegador. Chrome la ignora si la sincronizacion esta activa, por
//!   eso tambien `SyncDisabled`; `BrowserSignin = 0` impide iniciar sesion en el
//!   propio Chrome, asi la cuenta de Google solo vive en cookies.
//! - Edge: `ClearBrowsingDataOnExit` (borra todo al cerrar) y `SyncDisabled`.
//!   No se toca `BrowserSignin` para no romper el SSO de las cuentas Microsoft.
//! - Firefox: `SanitizeOnShutdown` con cookies y sesiones.
//! - Chrome y Edge dejan de quedarse en segundo plano (`BackgroundModeEnabled`,
//!   `StartupBoostEnabled`): si el proceso no termina, no hay "al cerrar".
//!
//! Al cerrar la sesion de Windows se cierran los navegadores y se borran los
//! datos; si se matan sin cerrar bien, Chrome y Edge los borran al abrir de
//! nuevo. Las extensiones y los marcadores no se tocan.

use anyhow::Result;

const CHROME: &str = r"HKLM:\SOFTWARE\Policies\Google\Chrome";
const EDGE: &str = r"HKLM:\SOFTWARE\Policies\Microsoft\Edge";
const FIREFOX: &str = r"HKLM:\SOFTWARE\Policies\Mozilla\Firefox\SanitizeOnShutdown";

/// Lista de datos que Chrome borra al salir (subclave con valores 1..n).
const CHROME_CLEAR_LIST: &str = "ClearBrowsingDataOnExitList";
const CHROME_CLEAR: &[&str] = &["cookies_and_other_site_data", "password_signin"];

/// (clave, valor DWORD, dato, descripcion).
const DWORDS: &[(&str, &str, u32, &str)] = &[
    (
        CHROME,
        "SyncDisabled",
        1,
        "Chrome: sincronização desativada",
    ),
    (
        CHROME,
        "BrowserSignin",
        0,
        "Chrome: sem início de sessão no navegador",
    ),
    (
        CHROME,
        "BackgroundModeEnabled",
        0,
        "Chrome: não fica em segundo plano",
    ),
    (
        EDGE,
        "ClearBrowsingDataOnExit",
        1,
        "Edge: apaga os dados ao fechar",
    ),
    (EDGE, "SyncDisabled", 1, "Edge: sincronização desativada"),
    (
        EDGE,
        "BackgroundModeEnabled",
        0,
        "Edge: não fica em segundo plano",
    ),
    (
        EDGE,
        "StartupBoostEnabled",
        0,
        "Edge: sem arranque acelerado",
    ),
    (FIREFOX, "Cookies", 1, "Firefox: apaga cookies ao fechar"),
    (FIREFOX, "Sessions", 1, "Firefox: apaga sessões ao fechar"),
];

/// Script que aplica las directivas.
fn enforce_script() -> String {
    let mut s = String::from("$ErrorActionPreference = 'Stop'\n");
    for (key, name, data, label) in DWORDS {
        s.push_str(&format!(
            "New-Item -Path '{key}' -Force | Out-Null\n\
             New-ItemProperty -Path '{key}' -Name '{name}' -PropertyType DWord -Value {data} -Force | Out-Null\n\
             Write-Output '  [ok] {label}'\n"
        ));
    }
    let list = format!(r"{CHROME}\{CHROME_CLEAR_LIST}");
    s.push_str(&format!(
        "Remove-Item -Path '{list}' -Recurse -Force -ErrorAction SilentlyContinue\n\
         New-Item -Path '{list}' -Force | Out-Null\n"
    ));
    for (i, item) in CHROME_CLEAR.iter().enumerate() {
        s.push_str(&format!(
            "New-ItemProperty -Path '{list}' -Name '{}' -PropertyType String -Value '{item}' -Force | Out-Null\n",
            i + 1
        ));
    }
    s.push_str("Write-Output '  [ok] Chrome: apaga cookies e palavras-passe ao fechar'\n");
    s.push_str(
        "Write-Output 'As contas Google deixam de ficar abertas ao terminar a sessão. Os navegadores abertos aplicam as diretivas quando reiniciarem.'\n",
    );
    s
}

/// Script que quita solo los valores que pone el agente.
fn revert_script() -> String {
    let mut s = String::new();
    for (key, name, _, _) in DWORDS {
        s.push_str(&format!(
            "Remove-ItemProperty -Path '{key}' -Name '{name}' -ErrorAction SilentlyContinue\n"
        ));
    }
    s.push_str(&format!(
        "Remove-Item -Path '{CHROME}\\{CHROME_CLEAR_LIST}' -Recurse -Force -ErrorAction SilentlyContinue\n\
         Write-Output 'Retiradas as diretivas de navegador do AEGN.'\n"
    ));
    s
}

/// Script que muestra el valor actual de cada directiva.
fn status_script() -> String {
    let mut s = String::new();
    for (key, name, data, label) in DWORDS {
        s.push_str(&format!(
            "$v = (Get-ItemProperty -Path '{key}' -Name '{name}' -ErrorAction SilentlyContinue).'{name}'\n\
             if ($v -eq {data}) {{ Write-Output '  [ok]    {label}' }} else {{ Write-Output '  [falta] {label}' }}\n"
        ));
    }
    s.push_str(&format!(
        "$l = Get-ItemProperty -Path '{CHROME}\\{CHROME_CLEAR_LIST}' -ErrorAction SilentlyContinue\n\
         if ($l) {{ Write-Output '  [ok]    Chrome: apaga cookies e palavras-passe ao fechar' }} else {{ Write-Output '  [falta] Chrome: apaga cookies e palavras-passe ao fechar' }}\n"
    ));
    s
}

/// Estado de las directivas de navegador.
pub fn status() -> Result<()> {
    #[cfg(windows)]
    {
        print!("{}", crate::ps::run(&status_script())?);
        Ok(())
    }

    #[cfg(not(windows))]
    {
        let _ = status_script;
        println!("[info] As diretivas de navegador só estão disponíveis no Windows.");
        Ok(())
    }
}

/// Aplica las directivas. Dry-run salvo `apply`.
pub fn enforce(apply: bool) -> Result<()> {
    if !apply {
        println!("[simulação] Ao fechar o navegador (e a sessão do Windows) seriam apagadas as");
        println!("[simulação] cookies, e com elas as contas Google abertas:");
        for (_, _, _, label) in DWORDS {
            println!("[simulação]   {label}");
        }
        println!("[simulação]   Chrome: apaga cookies e palavras-passe ao fechar");
        println!("[simulação] Execute com --aplicar para as aplicar (requer administrador).");
        return Ok(());
    }

    #[cfg(windows)]
    {
        print!("{}", crate::ps::run(&enforce_script())?);
        Ok(())
    }

    #[cfg(not(windows))]
    {
        let _ = enforce_script;
        println!("[info] As diretivas de navegador só estão disponíveis no Windows.");
        Ok(())
    }
}

/// Quita las directivas del agente. Dry-run salvo `apply`.
pub fn revert(apply: bool) -> Result<()> {
    if !apply {
        println!("[simulação] Seriam retiradas as diretivas de navegador do AEGN.");
        return Ok(());
    }

    #[cfg(windows)]
    {
        print!("{}", crate::ps::run(&revert_script())?);
        Ok(())
    }

    #[cfg(not(windows))]
    {
        let _ = revert_script;
        println!("[info] As diretivas de navegador só estão disponíveis no Windows.");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chrome_exige_sync_desactivado_para_borrar_al_salir() {
        assert!(DWORDS
            .iter()
            .any(|(k, n, d, _)| *k == CHROME && *n == "SyncDisabled" && *d == 1));
        assert!(CHROME_CLEAR.contains(&"cookies_and_other_site_data"));
    }

    #[test]
    fn revertir_quita_todo_lo_que_se_aplica() {
        let (aplica, revierte) = (enforce_script(), revert_script());
        for (_, name, _, _) in DWORDS {
            assert!(aplica.contains(&format!("-Name '{name}'")));
            assert!(revierte.contains(&format!("-Name '{name}'")));
        }
        assert!(revierte.contains(CHROME_CLEAR_LIST));
    }

    #[test]
    fn los_scripts_no_llevan_comillas_sin_cerrar() {
        for s in [enforce_script(), revert_script(), status_script()] {
            for line in s.lines() {
                assert_eq!(line.matches('\'').count() % 2, 0, "{line}");
            }
        }
    }
}
