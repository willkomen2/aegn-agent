//! AEGN Security — sistema de seguridad de los equipos de la Escola AEGN.
//!
//! Herramienta interna para que el administrador de sistemas mantenga las maquinas
//! de la escuela como material de estudio: auditar e desinstalar software no
//! autorizado y aplicar politicas de restriccion de ejecucion en carpetas de
//! usuario, usando mecanismos nativos de Windows (winget, AppLocker, directivas).
//!
//! Diseño:
//! - Todas las acciones destructivas son simulacion por defecto; hay que pasar
//!   `--aplicar` para ejecutarlas de verdad, y piden la contraseña del agente.
//! - Las operaciones de sistema requieren consola de administrador en Windows.
//! - Sin argumentos abre el menu TUI interactivo.
//! - La interfaz esta en portugues; los nombres en ingles de la v0.1 siguen
//!   funcionando como alias.

mod audit;
mod auth;
mod browser;
mod diag;
mod firewall;
mod install;
mod junk;
mod policy;
mod power;
mod process;
#[cfg(windows)]
mod ps;
mod rescue;
mod schedule;
mod tui;
mod update;

use anyhow::Result;
use clap::{Arg, ArgAction, CommandFactory, FromArgMatches, Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "aegn",
    version,
    about = "AEGN Security - sistema de segurança dos computadores da Escola AEGN",
    long_about = None,
    disable_help_flag = true,
    disable_version_flag = true,
    disable_help_subcommand = true
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Abre o menu interativo. É o modo por defeito.
    Menu,

    /// Executa o processo de manutenção completo.
    #[command(alias = "run")]
    Executar {
        /// Modo simples: salta o inventário inicial.
        #[arg(long, alias = "simple")]
        simples: bool,
        /// Não desinstalar o RustDesk.
        #[arg(long, alias = "no-rustdesk")]
        sem_rustdesk: bool,
        /// Não desinstalar o OpenCode.
        #[arg(long, alias = "no-opencode")]
        sem_opencode: bool,
        /// Não limpar o software da lista negra (Roblox, Spotify, Lively...).
        #[arg(long, alias = "no-clean")]
        sem_limpeza: bool,
        /// Não aplicar as políticas de execução (AppLocker).
        #[arg(long, alias = "no-policies")]
        sem_politicas: bool,
        /// AppLocker em modo auditoria: regista o que bloquearia, sem bloquear.
        #[arg(long = "so-auditoria", alias = "audit-only")]
        so_auditoria: bool,
        /// Não criar as regras de firewall contra acesso remoto.
        #[arg(long, alias = "no-firewall")]
        sem_firewall: bool,
        /// Não aplicar as diretivas que apagam as contas Google ao fechar o navegador.
        #[arg(long, alias = "no-browser")]
        sem_navegador: bool,
        /// Aplica as alterações (por defeito apenas simula). Pede a senha.
        #[arg(long, alias = "apply")]
        aplicar: bool,
    },

    /// Auditoria e remoção de software não autorizado.
    #[command(alias = "audit")]
    Auditoria {
        #[command(subcommand)]
        action: AuditAction,
    },

    /// Políticas de restrição de execução nas pastas dos utilizadores.
    #[command(alias = "policy")]
    Politica {
        #[command(subcommand)]
        action: PolicyAction,
    },

    /// Bloqueio de saída das ferramentas de acesso remoto no firewall.
    Firewall {
        #[command(subcommand)]
        action: FirewallAction,
    },

    /// Navegadores: apagar cookies e contas Google ao fechar (Chrome, Edge, Firefox).
    #[command(alias = "browser")]
    Navegador {
        #[command(subcommand)]
        action: BrowserAction,
    },

    /// Tarefa agendada (SYSTEM) que volta a aplicar o processo todos os dias.
    #[command(alias = "schedule")]
    Tarefa {
        #[command(subcommand)]
        action: ScheduleAction,
    },

    /// Estado de todas as proteções: AppLocker, firewall, navegador, tarefa e senha.
    #[command(alias = "status")]
    Estado,

    /// Desfaz tudo o que o agente aplicou (AppLocker, firewall, navegador e tarefa).
    #[command(alias = "revert")]
    Reverter {
        #[arg(long, alias = "apply")]
        aplicar: bool,
    },

    /// Resgate: desfaz tudo o que pode bloquear o computador ao iniciar sessão
    /// (esvazia o AppLocker, firewall, navegador, tarefa, perfis montados).
    /// Não pede a senha do AEGN, mas exige consola de administrador.
    #[command(alias = "resgatar", alias = "unlock")]
    Desbloquear {
        #[arg(long, alias = "apply")]
        aplicar: bool,
    },

    /// Repõe os botões Encerrar e Reiniciar (NoClose, HidePowerOptions, MDM,
    /// gpedit e o direito "Encerrar o sistema"). Também o faz o desbloquear.
    #[command(alias = "power")]
    Energia {
        #[arg(long, alias = "apply")]
        aplicar: bool,
    },

    /// Diagnóstico do computador (AppLocker, bloqueios, energia, resgate).
    /// Com --enviar publica-o em ntfy.sh, sem nomes de contas.
    #[command(alias = "diag")]
    Diagnostico {
        #[arg(long, alias = "send")]
        enviar: bool,
    },

    /// Instala um programa (.exe ou .msi) com uma conta de administrador. Pede a
    /// senha do AEGN e depois o Windows pede uma conta de administrador.
    #[command(alias = "install")]
    Instalar {
        /// Instalador a executar.
        ficheiro: std::path::PathBuf,
    },

    /// Senha de administração do agente (por defeito: admin).
    Senha {
        #[command(subcommand)]
        action: SenhaAction,
    },

    /// Procura uma versão nova no GitHub. Com --aplicar instala-a (sem administrador).
    #[command(alias = "update", args_conflicts_with_subcommands = true)]
    Atualizar {
        #[command(subcommand)]
        action: Option<UpdateAction>,
        /// Lança já a tarefa de atualização (corre como SYSTEM: sem UAC nem senha).
        #[arg(long, alias = "apply")]
        aplicar: bool,
    },
}

#[derive(Subcommand)]
enum UpdateAction {
    /// Estado da tarefa de atualização automática e últimas linhas do registo.
    #[command(alias = "status")]
    Estado,
}

#[derive(Subcommand)]
enum AuditAction {
    /// Lista o software instalado no computador (data, quem e editor).
    #[command(alias = "list")]
    Listar,
    /// Detalhe de um programa: versão, data, quem instalou, pasta e origem.
    #[command(alias = "detail")]
    Detalhe {
        /// Parte do nome do programa.
        nome: String,
    },
    /// Lista só o software não autorizado conhecido.
    #[command(alias = "suspects")]
    Suspeitos,
    /// Desinstala o software não autorizado e limpa restos e cursores.
    #[command(alias = "clean")]
    Limpar {
        /// Remove de facto (por defeito apenas simula). Pede a senha.
        #[arg(long, alias = "apply")]
        aplicar: bool,
    },
    /// Rasto da instalação: instaladores, eventos e arranque automático.
    #[command(alias = "evidence")]
    Rasto,
    /// Lista os membros do grupo local de Administradores.
    Admins,
    /// Quando e onde foi desinstalado cada programa.
    #[command(alias = "history")]
    Historico {
        /// Número máximo de linhas.
        #[arg(long, default_value_t = 50)]
        max: u32,
    },
    /// Desinstala um programa não autorizado pelo nome (ex.: RustDesk, OpenCode).
    #[command(alias = "remove")]
    Remover {
        /// Nome do programa a desinstalar.
        nome: String,
        /// Desinstala de facto (por defeito apenas simula). Pede a senha.
        #[arg(long, alias = "apply")]
        aplicar: bool,
    },
}

#[derive(Subcommand)]
enum PolicyAction {
    /// Mostra o estado atual das políticas AppLocker.
    #[command(alias = "status")]
    Estado,
    /// Lista negra: nega aos alunos o RustDesk, AnyDesk, TeamViewer, Roblox, Steam e Battle.net.
    #[command(alias = "enforce")]
    Impor {
        /// Aplica a política (por defeito apenas a mostra). Pede a senha.
        #[arg(long, alias = "apply")]
        aplicar: bool,
        /// Modo auditoria: regista o que bloquearia, sem bloquear.
        #[arg(long = "so-auditoria", alias = "audit-only")]
        so_auditoria: bool,
    },
    /// Volta a aplicar as regras do agente, no mesmo modo, se já estiverem
    /// aplicadas. O instalador usa-o para corrigir as de versões anteriores.
    #[command(alias = "refresh")]
    Atualizar {
        #[arg(long, alias = "apply")]
        aplicar: bool,
    },
    /// Retira as regras AppLocker do agente.
    #[command(alias = "revert")]
    Reverter {
        #[arg(long, alias = "apply")]
        aplicar: bool,
    },
    /// Últimos eventos do AppLocker (bloqueios e auditoria).
    #[command(alias = "events")]
    Eventos {
        /// Número máximo de eventos.
        #[arg(long, default_value_t = 30)]
        max: u32,
    },
}

#[derive(Subcommand)]
enum FirewallAction {
    /// Mostra as regras AEGN e o estado dos perfis do firewall.
    #[command(alias = "status")]
    Estado,
    /// Cria as regras de bloqueio de saída.
    #[command(alias = "enforce")]
    Impor {
        #[arg(long, alias = "apply")]
        aplicar: bool,
    },
    /// Elimina as regras AEGN.
    #[command(alias = "revert")]
    Reverter {
        #[arg(long, alias = "apply")]
        aplicar: bool,
    },
}

#[derive(Subcommand)]
enum BrowserAction {
    /// Mostra que diretivas de navegador estão aplicadas.
    #[command(alias = "status")]
    Estado,
    /// Aplica as diretivas: apagar cookies e contas ao fechar o navegador.
    #[command(alias = "enforce")]
    Impor {
        #[arg(long, alias = "apply")]
        aplicar: bool,
    },
    /// Retira as diretivas do AEGN.
    #[command(alias = "revert")]
    Reverter {
        #[arg(long, alias = "apply")]
        aplicar: bool,
    },
}

#[derive(Subcommand)]
enum ScheduleAction {
    /// Estado da tarefa e últimas linhas do registo.
    #[command(alias = "status")]
    Estado,
    /// Regista a tarefa (exige o aegn.exe dentro de Program Files).
    #[command(alias = "install")]
    Instalar {
        #[arg(long, alias = "apply")]
        aplicar: bool,
        /// A tarefa aplica o AppLocker em modo auditoria.
        #[arg(long = "so-auditoria", alias = "audit-only")]
        so_auditoria: bool,
    },
    /// Elimina a tarefa.
    #[command(alias = "remove")]
    Remover {
        #[arg(long, alias = "apply")]
        aplicar: bool,
    },
}

#[derive(Subcommand)]
enum SenhaAction {
    /// Altera a senha (pede a atual e a nova).
    Alterar,
    /// Indica se ainda se usa a senha por defeito.
    Estado,
    /// Verifica uma senha (código de saída 0 se for correta).
    Verificar,
}

impl Command {
    /// true si el comando va a cambiar el equipo y debe pedir la contraseña.
    fn applies(&self) -> bool {
        match self {
            Command::Executar { aplicar, .. }
            | Command::Reverter { aplicar }
            | Command::Energia { aplicar }
            | Command::Auditoria {
                action: AuditAction::Remover { aplicar, .. } | AuditAction::Limpar { aplicar },
            }
            | Command::Politica {
                action:
                    PolicyAction::Impor { aplicar, .. }
                    | PolicyAction::Atualizar { aplicar }
                    | PolicyAction::Reverter { aplicar },
            }
            | Command::Firewall {
                action: FirewallAction::Impor { aplicar } | FirewallAction::Reverter { aplicar },
            }
            | Command::Navegador {
                action: BrowserAction::Impor { aplicar } | BrowserAction::Reverter { aplicar },
            }
            | Command::Tarefa {
                action:
                    ScheduleAction::Instalar { aplicar, .. } | ScheduleAction::Remover { aplicar },
            } => *aplicar,
            Command::Instalar { .. } => true,
            _ => false,
        }
    }
}

/// Ayuda de clap en portugues: titulos, flags -h/-V y plantilla, en todos los
/// subcomandos.
fn localize(cmd: clap::Command) -> clap::Command {
    cmd.help_template("{about-with-newline}\nUso: {usage}\n\n{all-args}{after-help}")
        .subcommand_help_heading("Comandos")
        .subcommand_value_name("COMANDO")
        .disable_help_subcommand(true)
        .mut_args(|a| {
            let heading = if a.is_positional() {
                "Argumentos"
            } else {
                "Opções"
            };
            a.help_heading(heading)
        })
        .mut_subcommands(localize)
}

fn cli() -> clap::Command {
    let cmd = Cli::command()
        .arg(
            Arg::new("ajuda")
                .short('h')
                .long("help")
                .action(ArgAction::Help)
                .global(true)
                .help("Mostra esta ajuda"),
        )
        .arg(
            Arg::new("versao")
                .short('V')
                .long("version")
                .action(ArgAction::Version)
                .help("Mostra a versão"),
        );
    localize(cmd)
}

fn main() -> Result<()> {
    let cli = Cli::from_arg_matches(&cli().get_matches())?;

    if cli.command.as_ref().is_some_and(Command::applies) {
        auth::require()?;
    }

    match cli.command {
        None | Some(Command::Menu) => tui::run()?,
        Some(Command::Executar {
            simples,
            sem_rustdesk,
            sem_opencode,
            sem_limpeza,
            sem_politicas,
            so_auditoria,
            sem_firewall,
            sem_navegador,
            aplicar,
        }) => process::run(&process::ProcessConfig {
            simple: simples,
            uninstall_rustdesk: !sem_rustdesk,
            uninstall_opencode: !sem_opencode,
            clean_junk: !sem_limpeza,
            apply_policies: !sem_politicas,
            audit_only: so_auditoria,
            firewall: !sem_firewall,
            browser: !sem_navegador,
            apply: aplicar,
        })?,
        Some(Command::Auditoria { action }) => match action {
            AuditAction::Listar => audit::list()?,
            AuditAction::Detalhe { nome } => audit::detail(&nome)?,
            AuditAction::Suspeitos => audit::suspects()?,
            AuditAction::Limpar { aplicar } => audit::clean(aplicar)?,
            AuditAction::Rasto => audit::evidence()?,
            AuditAction::Admins => audit::admins()?,
            AuditAction::Historico { max } => audit::history(max)?,
            AuditAction::Remover { nome, aplicar } => audit::remove(&nome, aplicar)?,
        },
        Some(Command::Politica { action }) => match action {
            PolicyAction::Estado => policy::status()?,
            PolicyAction::Impor {
                aplicar,
                so_auditoria,
            } => policy::enforce(aplicar, so_auditoria)?,
            PolicyAction::Atualizar { aplicar } => policy::refresh(aplicar)?,
            PolicyAction::Reverter { aplicar } => policy::revert(aplicar)?,
            PolicyAction::Eventos { max } => policy::events(max)?,
        },
        Some(Command::Firewall { action }) => match action {
            FirewallAction::Estado => firewall::status()?,
            FirewallAction::Impor { aplicar } => firewall::enforce(aplicar)?,
            FirewallAction::Reverter { aplicar } => firewall::revert(aplicar)?,
        },
        Some(Command::Navegador { action }) => match action {
            BrowserAction::Estado => browser::status()?,
            BrowserAction::Impor { aplicar } => browser::enforce(aplicar)?,
            BrowserAction::Reverter { aplicar } => browser::revert(aplicar)?,
        },
        Some(Command::Tarefa { action }) => match action {
            ScheduleAction::Estado => schedule::status()?,
            ScheduleAction::Instalar {
                aplicar,
                so_auditoria,
            } => schedule::install(aplicar, so_auditoria)?,
            ScheduleAction::Remover { aplicar } => schedule::remove(aplicar)?,
        },
        Some(Command::Estado) => process::status_all()?,
        Some(Command::Reverter { aplicar }) => process::revert_all(aplicar)?,
        Some(Command::Instalar { ficheiro }) => install::run(&ficheiro)?,
        Some(Command::Desbloquear { aplicar }) => rescue::run(aplicar)?,
        Some(Command::Energia { aplicar }) => power::run(aplicar)?,
        Some(Command::Diagnostico { enviar }) => diag::run(enviar)?,
        Some(Command::Senha { action }) => match action {
            SenhaAction::Alterar => auth::change()?,
            SenhaAction::Estado => auth::status()?,
            SenhaAction::Verificar => auth::check()?,
        },
        Some(Command::Atualizar { action, aplicar }) => match action {
            Some(UpdateAction::Estado) => update::status()?,
            None => update::run(aplicar)?,
        },
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Command {
        let m = cli()
            .try_get_matches_from(std::iter::once("aegn").chain(args.iter().copied()))
            .unwrap();
        Cli::from_arg_matches(&m).unwrap().command.unwrap()
    }

    #[test]
    fn solo_aplicar_pide_contrasena() {
        assert!(!parse(&["executar"]).applies());
        assert!(parse(&["executar", "--aplicar"]).applies());
        assert!(parse(&["reverter", "--aplicar"]).applies());
        assert!(parse(&["tarefa", "instalar", "--aplicar"]).applies());
        assert!(!parse(&["estado"]).applies());
        assert!(!parse(&["politica", "eventos"]).applies());
        assert!(!parse(&["auditoria", "historico"]).applies());
        assert!(parse(&["executar", "--sem-limpeza", "--aplicar"]).applies());
        // Instala o release oficial pela tarefa SYSTEM: não pede a senha.
        assert!(!parse(&["atualizar", "--aplicar"]).applies());
        assert!(!parse(&["atualizar", "estado"]).applies());
        assert!(parse(&["navegador", "impor", "--aplicar"]).applies());
        assert!(!parse(&["navegador", "estado"]).applies());
        assert!(parse(&["energia", "--aplicar"]).applies());
        assert!(!parse(&["energia"]).applies());
        // Só lê e envia: não pede a senha (corre na tarefa SYSTEM).
        assert!(!parse(&["diagnostico", "--enviar"]).applies());
    }

    #[test]
    fn la_limpieza_solo_pide_contrasena_si_aplica() {
        assert!(!parse(&["auditoria", "limpar"]).applies());
        assert!(parse(&["auditoria", "limpar", "--aplicar"]).applies());
        assert!(parse(&["auditoria", "clean", "--apply"]).applies());
        assert!(!parse(&["auditoria", "suspeitos"]).applies());
        assert!(!parse(&["auditoria", "rasto"]).applies());
        assert!(!parse(&["auditoria", "detalhe", "Roblox"]).applies());
    }

    #[test]
    fn la_ayuda_es_valida() {
        cli().debug_assert();
    }

    #[test]
    fn los_nombres_de_la_v01_siguen_funcionando() {
        assert!(parse(&["run", "--apply", "--audit-only", "--simple"]).applies());
        assert!(parse(&["policy", "enforce", "--apply"]).applies());
        assert!(!parse(&["status"]).applies());
        assert!(parse(&["schedule", "install", "--apply"]).applies());
    }
}
