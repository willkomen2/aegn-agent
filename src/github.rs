//! Interaccion con la API de GitHub para gestionar el repositorio del proyecto.
//!
//! El token personal (PAT) se lee SIEMPRE de la variable de entorno
//! `GITHUB_TOKEN`. Nunca se acepta por argumento ni se imprime: evitar
//! credenciales en texto plano en historiales de shell o logs.

use anyhow::{anyhow, Context, Result};

const API_BASE: &str = "https://api.github.com";
const USER_AGENT: &str = "aegn-agent (Escola AEGN IT)";

/// Recupera el token desde el entorno, fallando con un mensaje claro si falta.
fn token() -> Result<String> {
    std::env::var("GITHUB_TOKEN").map_err(|_| {
        anyhow!("Falta la variable de entorno GITHUB_TOKEN. Exportala antes de ejecutar (no se acepta por argumento).")
    })
}

/// Verifica el token consultando /user e imprime el login autenticado.
pub fn whoami() -> Result<()> {
    let token = token()?;

    let response = ureq::get(&format!("{API_BASE}/user"))
        .set("Authorization", &format!("Bearer {token}"))
        .set("User-Agent", USER_AGENT)
        .set("Accept", "application/vnd.github+json")
        .set("X-GitHub-Api-Version", "2022-11-28")
        .call();

    match response {
        Ok(resp) => {
            let body: serde_json::Value =
                resp.into_json().context("respuesta de GitHub no es JSON valido")?;
            let login = body
                .get("login")
                .and_then(|v| v.as_str())
                .unwrap_or("<desconocido>");
            println!("[ok] Autenticado en GitHub como: {login}");
            Ok(())
        }
        Err(ureq::Error::Status(401, _)) => {
            Err(anyhow!("Token invalido o expirado (HTTP 401). Revisa GITHUB_TOKEN."))
        }
        Err(ureq::Error::Status(code, _)) => {
            Err(anyhow!("GitHub respondio con HTTP {code}."))
        }
        Err(e) => Err(anyhow!("Error de red al contactar GitHub: {e}")),
    }
}
