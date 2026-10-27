//! Clasificación del software: qué es sospechoso y qué se conserva.
//!
//! La lista es explícita y auditable. Solo se desinstala lo que coincide con
//! una regla de `RULES`; todo lo demás se deja intacto. `KEEP` es una red de
//! seguridad: aunque una regla coincidiera, el software del sistema (Windows,
//! drivers, Tailscale, Git...) nunca se toca.
//!
//! La comparación es en minúsculas y por "contiene", para cubrir las variantes
//! que añaden los instaladores ("Roblox Player for Aluno(a)", "Spotify Music",
//! "12030rocksdanister.LivelyWallpaper"...).

/// Un motivo de desinstalación. `label` es lo que se muestra al administrador.
pub struct Rule {
    /// Identificador corto y estable (para pruebas y salida).
    #[cfg_attr(not(test), allow(dead_code))]
    pub id: &'static str,
    /// Descripción en portugués para la consola.
    pub label: &'static str,
    /// Fragmentos que, si aparecen en el nombre, activan la regla.
    pub patterns: &'static [&'static str],
}

/// Lista negra de la escuela: ocio, acceso remoto no autorizado y utilidades
/// dudosas. El orden importa: gana la primera regla que coincida.
pub static RULES: &[Rule] = &[
    Rule {
        id: "roblox",
        label: "jogo (Roblox)",
        patterns: &["roblox"],
    },
    Rule {
        id: "spotify",
        label: "música (Spotify)",
        patterns: &["spotify"],
    },
    Rule {
        id: "lively",
        label: "fundos animados (Lively Wallpaper)",
        patterns: &["lively wallpaper", "livelywallpaper", "rocksdanister"],
    },
    Rule {
        id: "cursor",
        label: "cursor personalizado",
        patterns: &["custom cursor", "customcursor"],
    },
    Rule {
        id: "jogos",
        label: "jogo / lançador de jogos",
        patterns: &[
            "steam",
            "epic games",
            "riot client",
            "valorant",
            "minecraft",
            "tlauncher",
            "fortnite",
            "battle.net",
            "ea app",
            "gog galaxy",
        ],
    },
    Rule {
        id: "p2p",
        label: "partilha P2P",
        patterns: &["utorrent", "bittorrent", "qbittorrent"],
    },
    Rule {
        id: "limpeza",
        label: "utilitário de limpeza duvidoso",
        patterns: &[
            "ccleaner",
            "driver booster",
            "advanced systemcare",
            "glary utilities",
        ],
    },
    Rule {
        id: "remoto",
        label: "acesso remoto não autorizado",
        patterns: &["rustdesk", "anydesk", "teamviewer"],
    },
    Rule {
        id: "emulador",
        label: "emulador de Android",
        patterns: &["bluestacks", "ldplayer", "noxplayer", "memu play"],
    },
];

/// Software que nunca se desinstala, aunque una regla lo pillara. Se compara
/// con el nombre y con el editor.
pub static KEEP: &[&str] = &[
    "minecraft education",
    "tailscale",
    "microsoft",
    "windows",
    "hp inc",
    "hp ",
    "nvidia",
    "intel",
    "realtek",
    "visual c++",
    "office",
    "onedrive",
    "teams",
    "edge",
    "chrome",
    "github",
    "git development",
];

/// Devuelve la regla que explica por qué un programa no es admisible.
pub fn classify(name: &str) -> Option<&'static Rule> {
    let n = name.to_lowercase();
    RULES
        .iter()
        .find(|r| r.patterns.iter().any(|p| n.contains(*p)))
}

/// true si el programa pertenece al sistema o a una herramienta aprobada.
/// Se mira el nombre y el editor: "Git" no lleva la palabra "Windows", pero su
/// editor es "The Git Development Community".
pub fn kept(name: &str, publisher: &str) -> bool {
    let n = name.to_lowercase();
    let p = publisher.to_lowercase();
    KEEP.iter()
        .any(|k| n.contains(*k) || (!p.is_empty() && p.contains(*k)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detecta_lo_que_la_escuela_no_quiere() {
        for nombre in [
            "Roblox Player for Aluno(a)",
            "Roblox Studio",
            "Spotify Music",
            "12030rocksdanister.LivelyWallpaper",
            "5575M.K.CustomCursors-ChooseorCreateyourpackown",
            "RustDesk",
            "Steam",
        ] {
            assert!(classify(nombre).is_some(), "deberia marcar: {nombre}");
        }
    }

    #[test]
    fn no_toca_el_sistema() {
        for nombre in ["Tailscale", "Git", "Microsoft Edge", "HP Wolf Security"] {
            assert!(classify(nombre).is_none(), "no deberia marcar: {nombre}");
        }
    }

    #[test]
    fn la_lista_blanca_manda() {
        assert!(kept("Tailscale", "Tailscale Inc."));
        assert!(kept("Git", "The Git Development Community"));
        assert!(kept("NVIDIA Controlador gráfico", "NVIDIA Corporation"));
        // Spotify es de Spotify AB: no entra en la lista blanca.
        assert!(!kept("Spotify Music", "Spotify AB"));
        assert!(!kept("Roblox Player", "Roblox Corporation"));
    }

    #[test]
    fn la_regla_mas_especifica_gana() {
        assert_eq!(classify("Lively Wallpaper").map(|r| r.id), Some("lively"));
        assert_eq!(
            classify("5575M.K.CustomCursors").map(|r| r.id),
            Some("cursor")
        );
        assert_eq!(classify("RustDesk").map(|r| r.id), Some("remoto"));
    }
}
