//! Contraseña de administración del agente.
//!
//! Todo lo que cambia el equipo (`--aplicar`) pide esta contraseña, además de
//! la consola de administrador. Si nunca se ha cambiado, vale `admin`.
//!
//! Se guarda solo el hash PBKDF2-HMAC-SHA256 con sal aleatoria:
//! - Windows: `HKLM\SOFTWARE\AEGN\Seguranca`, valor `Senha` (solo los admins
//!   escriben en HKLM).
//! - Otros sistemas (desarrollo): `~/.config/aegn/senha`.
//!
//! Limite: un administrador que borre ese valor vuelve a la contraseña por
//! defecto. Protege del uso casual o accidental, no de un admin decidido.
//!
//! Sin terminal (menu TUI, scripts de instalacion) la contraseña llega por la
//! variable de entorno `AEGN_SENHA`. La tarea programada corre como SYSTEM y no
//! la necesita.

use anyhow::{bail, Context, Result};
use sha2::Sha256;

pub const DEFAULT: &str = "admin";
pub const ENV: &str = "AEGN_SENHA";
/// Contraseña nueva para `senha alterar` sin terminal (instalador).
pub const ENV_NEW: &str = "AEGN_SENHA_NOVA";

const ITERATIONS: u32 = 120_000;
const MIN_LEN: usize = 4;

fn derive(password: &str, salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut out = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, iterations, &mut out);
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

/// Hash con formato `pbkdf2-sha256$iteraciones$sal$hash`.
fn hash(password: &str) -> Result<String> {
    let mut salt = [0u8; 16];
    getrandom::getrandom(&mut salt)
        .map_err(|e| anyhow::anyhow!("não foi possível gerar o sal: {e}"))?;
    Ok(format!(
        "pbkdf2-sha256${ITERATIONS}${}${}",
        hex(&salt),
        hex(&derive(password, &salt, ITERATIONS))
    ))
}

/// Comprueba una contraseña contra un hash guardado, en tiempo constante.
fn matches(password: &str, stored: &str) -> bool {
    let parts: Vec<&str> = stored.trim().split('$').collect();
    let [scheme, iter, salt, expected] = parts[..] else {
        return false;
    };
    let (Ok(iter), Some(salt), Some(expected)) = (iter.parse(), unhex(salt), unhex(expected))
    else {
        return false;
    };
    if scheme != "pbkdf2-sha256" || expected.len() != 32 {
        return false;
    }
    let got = derive(password, &salt, iter);
    got.iter()
        .zip(&expected)
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

/// Comprueba una contraseña contra la guardada (o `admin` si no hay ninguna).
pub fn verify(password: &str) -> Result<bool> {
    Ok(match store::load()? {
        Some(stored) => matches(password, &stored),
        None => password == DEFAULT,
    })
}

/// true si todavia vale la contraseña por defecto.
pub fn is_default() -> Result<bool> {
    verify(DEFAULT)
}

/// Exige la contraseña antes de un cambio real: de `AEGN_SENHA` si existe, si
/// no la pide en la consola (3 intentos). SYSTEM (tarea programada) no la pide.
pub fn require() -> Result<()> {
    if running_as_system() {
        return Ok(());
    }
    if let Ok(pw) = std::env::var(ENV) {
        if verify(&pw)? {
            return Ok(());
        }
        bail!("Senha incorreta (variável {ENV}).");
    }
    for attempt in 1..=3 {
        let pw = rpassword::prompt_password("Senha de administração do AEGN: ")
            .context("não foi possível ler a senha da consola")?;
        if verify(&pw)? {
            if pw == DEFAULT {
                println!("[aviso] Ainda está a usar a senha por defeito. Altere-a com: aegn senha alterar");
            }
            return Ok(());
        }
        if attempt < 3 {
            println!("[erro] Senha incorreta. Tente novamente.");
        }
    }
    bail!("Senha incorreta. Operação cancelada.")
}

/// `aegn senha alterar`: pide la actual y la nueva dos veces (o las toma de
/// AEGN_SENHA / AEGN_SENHA_NOVA) y guarda el hash.
pub fn change() -> Result<()> {
    let current = match std::env::var(ENV) {
        Ok(pw) => pw,
        Err(_) => rpassword::prompt_password("Senha atual: ")?,
    };
    if !verify(&current)? {
        bail!("Senha atual incorreta.");
    }
    let new = match std::env::var(ENV_NEW) {
        Ok(pw) => pw,
        Err(_) => {
            let a = rpassword::prompt_password("Nova senha: ")?;
            let b = rpassword::prompt_password("Repita a nova senha: ")?;
            if a != b {
                bail!("As senhas não coincidem.");
            }
            a
        }
    };
    if new.chars().count() < MIN_LEN {
        bail!("A nova senha tem de ter pelo menos {MIN_LEN} caracteres.");
    }
    store::save(&hash(&new)?)?;
    println!("[ok] Senha alterada.");
    Ok(())
}

/// `aegn senha verificar`: codigo de salida 0 si la contraseña es correcta.
/// Lo usa el instalador antes de actualizar una instalacion existente.
pub fn check() -> Result<()> {
    let pw = match std::env::var(ENV) {
        Ok(pw) => pw,
        Err(_) => rpassword::prompt_password("Senha: ")?,
    };
    if !verify(&pw)? {
        bail!("Senha incorreta.");
    }
    println!("[ok] Senha correta.");
    Ok(())
}

/// `aegn senha estado`.
pub fn status() -> Result<()> {
    if is_default()? {
        println!("[aviso] Senha por defeito ('{DEFAULT}'). Altere-a com: aegn senha alterar");
    } else {
        println!("[ok] Senha personalizada definida.");
    }
    println!("[info] Guardada em: {}", store::LOCATION);
    Ok(())
}

/// La tarea programada corre como SYSTEM sin consola: no se le pide contraseña.
/// Se pregunta a Windows por el token del proceso (no se fia de USERNAME, que
/// cualquiera puede cambiar).
#[cfg(windows)]
fn running_as_system() -> bool {
    crate::ps::run("[Security.Principal.WindowsIdentity]::GetCurrent().IsSystem")
        .map(|out| out.trim().eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

#[cfg(not(windows))]
fn running_as_system() -> bool {
    false
}

#[cfg(windows)]
mod store {
    use anyhow::{Context, Result};
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY};
    use winreg::RegKey;

    const KEY: &str = r"SOFTWARE\AEGN\Seguranca";
    const VALUE: &str = "Senha";
    pub const LOCATION: &str = r"HKLM\SOFTWARE\AEGN\Seguranca (Senha)";

    pub fn load() -> Result<Option<String>> {
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        match hklm.open_subkey_with_flags(KEY, KEY_READ | KEY_WOW64_64KEY) {
            Ok(key) => Ok(key.get_value::<String, _>(VALUE).ok()),
            Err(_) => Ok(None),
        }
    }

    pub fn save(hash: &str) -> Result<()> {
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let (key, _) = hklm
            .create_subkey_with_flags(KEY, winreg::enums::KEY_ALL_ACCESS | KEY_WOW64_64KEY)
            .context("não foi possível escrever em HKLM (execute como administrador)")?;
        key.set_value(VALUE, &hash.to_string())
            .context("não foi possível guardar a senha")
    }
}

#[cfg(not(windows))]
mod store {
    use anyhow::{Context, Result};
    use std::path::PathBuf;

    pub const LOCATION: &str = "~/.config/aegn/senha";

    fn path() -> PathBuf {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
            .unwrap_or_else(|| PathBuf::from("."))
            .join("aegn")
            .join("senha")
    }

    pub fn load() -> Result<Option<String>> {
        Ok(std::fs::read_to_string(path()).ok())
    }

    pub fn save(hash: &str) -> Result<()> {
        let p = path();
        if let Some(dir) = p.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(&p, hash)
            .with_context(|| format!("não foi possível escrever {}", p.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_verifica_solo_la_contrasena_correcta() {
        let h = hash("segredo-aegn").unwrap();
        assert!(h.starts_with("pbkdf2-sha256$"));
        assert!(matches("segredo-aegn", &h));
        assert!(!matches("segredo-aegm", &h));
        assert!(!matches("", &h));
    }

    #[test]
    fn la_sal_cambia_en_cada_hash() {
        assert_ne!(hash("admin").unwrap(), hash("admin").unwrap());
    }

    #[test]
    fn hash_corrupto_no_verifica() {
        for bad in [
            "",
            "admin",
            "pbkdf2-sha256$x$00$00",
            "md5$1$00$00",
            "pbkdf2-sha256$1$zz$00",
        ] {
            assert!(!matches("admin", bad), "aceptado: {bad}");
        }
    }
}
