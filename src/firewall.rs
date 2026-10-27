//! Bloqueo saliente de herramientas de acceso remoto en el Firewall de Windows.
//!
//! Complementa a AppLocker: aunque un alumno consiga ejecutar RustDesk,
//! AnyDesk o TeamViewer, no podra conectar con sus servidores publicos por los
//! puertos propios de cada herramienta. Las reglas van en el grupo
//! `AEGN-RemoteAccess`, asi se pueden listar y retirar sin tocar las demas.
//!
//! Limite conocido: AnyDesk y TeamViewer tambien pueden salir por 443; para
//! cortarlos del todo hace falta filtrado por dominio en el proxy o el DNS.

use anyhow::Result;

const GROUP: &str = "AEGN-RemoteAccess";

/// (herramienta, protocolo, puertos remotos).
const BLOCKS: &[(&str, &str, &str)] = &[
    ("RustDesk", "TCP", "21114-21119"),
    ("RustDesk", "UDP", "21116"),
    ("AnyDesk", "TCP", "6568"),
    ("TeamViewer", "TCP", "5938"),
    ("TeamViewer", "UDP", "5938"),
];

/// Muestra las reglas AEGN y si el firewall esta activo en cada perfil.
pub fn status() -> Result<()> {
    #[cfg(windows)]
    {
        let ps = format!(
            r#"
Get-NetFirewallProfile | ForEach-Object {{
  $state = if ($_.Enabled) {{ 'ativo' }} else {{ 'DESATIVADO' }}
  Write-Output ("Perfil " + $_.Name + ": " + $state)
  if (-not $_.Enabled) {{ Write-Output "[aviso] Com o perfil $($_.Name) desativado, as regras AEGN não atuam." }}
}}
Write-Output "--- Regras {GROUP} ---"
$rules = @(Get-NetFirewallRule -Group '{GROUP}' -ErrorAction SilentlyContinue)
if ($rules.Count -eq 0) {{ Write-Output '  (nenhuma)' }}
$rules | ForEach-Object {{ "  " + $_.DisplayName + "  [" + $_.Enabled + "]" }}
"#
        );
        print!("{}", crate::ps::run(&ps)?);
        Ok(())
    }

    #[cfg(not(windows))]
    {
        println!("[info] O estado do firewall só está disponível no Windows.");
        Ok(())
    }
}

/// Crea (o recrea) las reglas de bloqueo saliente. Dry-run salvo `apply`.
pub fn enforce(apply: bool) -> Result<()> {
    if !apply {
        println!("[simulação] Seria bloqueada a saída na Firewall do Windows (grupo {GROUP}):");
        for (tool, proto, ports) in BLOCKS {
            println!("[simulação]   {tool:<10} {proto} {ports}");
        }
        println!("[simulação] Execute com --aplicar para criar as regras (requer administrador).");
        return Ok(());
    }

    #[cfg(windows)]
    {
        let mut ps = format!(
            "$ErrorActionPreference = 'Stop'\n\
             Get-NetFirewallRule -Group '{GROUP}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule\n"
        );
        for (tool, proto, ports) in BLOCKS {
            ps.push_str(&format!(
                "New-NetFirewallRule -DisplayName 'AEGN: bloquear {tool} {proto} {ports}' -Group '{GROUP}' \
                 -Direction Outbound -Action Block -Protocol {proto} -RemotePort {ports} -Profile Any | Out-Null\n"
            ));
        }
        ps.push_str(&format!(
            "Write-Output \"Criadas {} regras de bloqueio de saída ({GROUP}).\"\n\
             if (Get-NetFirewallProfile | Where-Object {{ -not $_.Enabled }}) {{ \
             Write-Output '[aviso] Há perfis do firewall desativados: as regras não atuam neles.' }}\n",
            BLOCKS.len()
        ));
        print!("{}", crate::ps::run(&ps)?);
        Ok(())
    }

    #[cfg(not(windows))]
    {
        println!("[info] O firewall só está disponível no Windows.");
        Ok(())
    }
}

/// Retira las reglas del grupo AEGN. Dry-run salvo `apply`.
pub fn revert(apply: bool) -> Result<()> {
    if !apply {
        println!("[simulação] Seriam eliminadas as regras de firewall do grupo {GROUP}.");
        return Ok(());
    }

    #[cfg(windows)]
    {
        let ps = format!(
            "$r = @(Get-NetFirewallRule -Group '{GROUP}' -ErrorAction SilentlyContinue)\n\
             $r | Remove-NetFirewallRule\n\
             Write-Output (\"Eliminadas \" + $r.Count + \" regras de firewall AEGN.\")"
        );
        print!("{}", crate::ps::run(&ps)?);
        Ok(())
    }

    #[cfg(not(windows))]
    {
        println!("[info] O firewall só está disponível no Windows.");
        Ok(())
    }
}
