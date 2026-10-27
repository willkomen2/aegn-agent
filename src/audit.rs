//! Auditoria y remocion de software no autorizado.
//!
//! En Windows se apoya en mecanismos legitimos:
//! - Inventario: claves de desinstalacion del registro (`Get-ItemProperty` sobre
//!   `...\Uninstall`), que es la misma fuente que usa "Programas y
//!   caracteristicas", mas los paquetes de la Microsoft Store (`Get-AppxPackage`).
//! - Atribucion: fecha de instalacion (InstallDate, ultima escritura de la clave
//!   o creacion de la carpeta), usuario dueno de la clave (HKCU = sesion actual,
//!   HKLM = instalacion de administrador) y origen (`InstallSource`).
//! - Desinstalacion, para cada coincidencia por nombre:
//!   - instalacion de maquina: su `UninstallString` en modo silencioso;
//!   - instalacion por usuario (Roblox, Spotify...): se recorren todos los
//!     perfiles con la sesion abierta (nunca se carga el NTUSER.DAT de los
//!     demas: si la descarga falla, Windows no puede abrir ese perfil y el
//!     inicio de sesion se congela) y se borra
//!     la carpeta de AppData del programa y su clave, porque su desinstalador
//!     correria en el perfil del administrador y no en el del alumno;
//!   - app de la Store: `Remove-AppxPackage -AllUsers`;
//!   - si nada coincide, `winget uninstall` como ultimo recurso.
//! - Historial: cada desinstalacion real se anota en `logs\desinstalacoes.csv`
//!   junto al ejecutable, con fecha, perfil y version.
//!
//! Toda remocion es dry-run salvo que se pase `apply = true`.

use crate::junk;
use anyhow::Result;

/// Una entrada del inventario. Incluye lo necesario para atribuir la
/// instalacion: cuando, con que usuario y desde que instalador.
#[derive(Clone, Debug)]
pub struct App {
    /// HKLM64 / HKLM32 / HKCU / APPX.
    pub hive: String,
    pub name: String,
    pub version: String,
    pub publisher: String,
    /// Fecha de instalacion en formato AAAA-MM-DD.
    pub installed: String,
    /// Tamano estimado en MB (vacio si el instalador no lo declara).
    pub size_mb: String,
    pub location: String,
    pub source: String,
    /// Comando de desinstalacion (o PackageFullName en las apps de la Store).
    pub uninstall: String,
    /// Quien lo instalo: el usuario de la sesion (HKCU/APPX) o "todos (admin)".
    pub who: String,
}

/// Programas no autorizados que `clean` busca ademas por nombre en todos los
/// perfiles y en la Store: el inventario solo ve la sesion actual, y la tarea
/// programada corre como SYSTEM, asi que no veria lo que un alumno instalo en su
/// AppData. El texto debe aparecer en el nombre del programa.
#[cfg_attr(not(windows), allow(dead_code))]
/// Minecraft queda fuera a proposito: muchas escuelas usan Minecraft Education.
pub const APPS: &[&str] = &[
    // Personalizacion y musica.
    "Lively Wallpaper",
    "Custom Cursor",
    "CursorFX",
    "Spotify",
    // Juegos y sus lanzadores.
    "Roblox",
    "Steam",
    "Riot Client",
    "Riot Vanguard",
    "VALORANT",
    "League of Legends",
    "Epic Games",
    "Battle.net",
    "EA app",
    "Ubisoft Connect",
    "GOG Galaxy",
];

/// Ruta del historial de desinstalaciones (junto al ejecutable).
#[cfg(windows)]
fn history_path() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|e| {
            e.parent()
                .map(|d| d.join("logs").join("desinstalacoes.csv"))
        })
        .map(|p| p.display().to_string())
        .unwrap_or_default()
}

/// Comillas simples escapadas para un literal de PowerShell.
#[cfg(windows)]
fn q(s: &str) -> String {
    s.replace('\'', "''")
}

/// Lista el software instalado con fecha, usuario y editor.
pub fn list() -> Result<()> {
    let mut apps = inventory()?;
    if apps.is_empty() {
        println!("[info] Nenhum programa encontrado (o inventário só existe no Windows).");
        return Ok(());
    }
    apps.sort_by_key(|a| a.name.to_lowercase());

    println!(
        "{:<6} {:<38} {:<11} {:<14} {:<20} MB",
        "ORIGEM", "PROGRAMA", "INSTALADO", "QUEM", "EDITOR"
    );
    for a in &apps {
        println!(
            "{:<6} {:<38} {:<11} {:<14} {:<20} {}",
            a.hive,
            corta(&a.name, 38),
            a.installed,
            corta(&a.who, 14),
            corta(&a.publisher, 20),
            a.size_mb
        );
    }
    Ok(())
}

/// Detalle de todo lo que se sabe de un programa (o de los que coincidan).
pub fn detail(name: &str) -> Result<()> {
    let buscado = name.to_lowercase();
    let apps: Vec<App> = inventory()?
        .into_iter()
        .filter(|a| a.name.to_lowercase().contains(buscado.as_str()))
        .collect();
    if apps.is_empty() {
        println!("[info] Nenhum programa corresponde a '{name}'.");
        return Ok(());
    }
    for a in &apps {
        println!("{}", a.name);
        println!("  registo     : {}", a.hive);
        println!("  versão      : {}", vazio(&a.version));
        println!("  editor      : {}", vazio(&a.publisher));
        println!("  instalado   : {}  (por {})", vazio(&a.installed), a.who);
        println!(
            "  tamanho     : {} MB",
            if a.size_mb.is_empty() {
                "?"
            } else {
                a.size_mb.as_str()
            }
        );
        println!("  pasta       : {}", vazio(&a.location));
        println!("  origem      : {}", vazio(&a.source));
        println!("  desinstalar : {}", vazio(&a.uninstall));
        println!(
            "  motivo      : {}",
            junk::classify(&a.name).map_or("—", |r| r.label)
        );
        println!();
    }
    Ok(())
}

/// Solo el software que incumple las reglas de la escuela.
pub fn suspects() -> Result<()> {
    let mut apps: Vec<App> = inventory()?.into_iter().filter(flagged_app).collect();
    if apps.is_empty() {
        println!("[ok] Nenhum software não autorizado conhecido está instalado.");
        return Ok(());
    }
    apps.sort_by_key(|a| a.name.to_lowercase());

    println!("-- Software não autorizado conhecido --");
    for a in &apps {
        let motivo = junk::classify(&a.name).map_or("lista negra", |r| r.label);
        println!(
            "  {:<38} {:<11} {:<14} {:<6} [{}]",
            corta(&a.name, 38),
            a.installed,
            corta(&a.who, 14),
            a.hive,
            motivo
        );
    }
    println!();
    println!("Para remover tudo: aegn auditoria limpar --aplicar");
    Ok(())
}

/// Desinstala el software no autorizado y limpia los restos (carpetas de datos,
/// cursores personalizados y su esquema). Dry-run salvo `apply`.
pub fn clean(apply: bool) -> Result<()> {
    let flagged: Vec<App> = inventory()?.into_iter().filter(flagged_app).collect();

    println!("-- Software não autorizado conhecido --");
    if flagged.is_empty() {
        println!("[ok] Nenhum dos programas da lista negra está instalado.");
    }

    let mut failures = 0usize;
    for a in &flagged {
        let motivo = junk::classify(&a.name).map_or("lista negra", |r| r.label);
        println!(
            "  {} {}  ·  instalado {}  ·  {}{}",
            a.name,
            a.version,
            vazio(&a.installed),
            a.who,
            if a.publisher.is_empty() {
                String::new()
            } else {
                format!("  ·  {}", a.publisher)
            }
        );
        println!("      motivo: {motivo}");
        if !apply {
            println!("      [simulação] seria desinstalado");
            continue;
        }
        match remove_app(a) {
            Ok(()) => println!("      [ok] removido"),
            Err(e) => {
                println!("      [erro] {e}");
                failures += 1;
            }
        }
    }
    println!();

    println!("-- Todos os perfis e Microsoft Store --");
    failures += clean_all_profiles(apply)?;
    println!();

    println!("-- Restos: pastas de dados e cursores descarregados --");
    print!("{}", run_or_note(&cleanup_script(apply))?);
    println!();

    println!("-- Cursor personalizado: repor o esquema do Windows --");
    print!("{}", run_or_note(&cursor_script(apply))?);
    println!();

    if !apply {
        println!("[simulação] Execute com --aplicar para remover de facto (requer administrador).");
    } else if failures > 0 {
        anyhow::bail!("{failures} programa(s) não puderam ser removidos; veja a saída acima.");
    }
    Ok(())
}

/// Busca `APPS` en los perfiles con sesion abierta y en la Store, y los
/// quita si `apply`. Devuelve cuantos programas fallaron.
#[cfg(windows)]
fn clean_all_profiles(apply: bool) -> Result<usize> {
    let mut failures = 0;
    let mut found = false;
    for name in APPS {
        match crate::ps::run(&uninstall_script(name, apply)) {
            Ok(out) => {
                let out: Vec<&str> = out
                    .lines()
                    .filter(|l| !l.starts_with("NAO_ENCONTRADO"))
                    .collect();
                if !out.is_empty() {
                    found = true;
                    println!("{}", out.join("\n"));
                }
            }
            Err(e) => {
                found = true;
                println!("[erro] {name}: {e:#}");
                failures += 1;
            }
        }
    }
    if !found {
        println!("[ok] Nada encontrado noutros perfis nem na Store.");
    }
    Ok(failures)
}

#[cfg(not(windows))]
fn clean_all_profiles(_apply: bool) -> Result<usize> {
    println!("[info] Esta operação só está disponível no Windows.");
    Ok(0)
}

/// Rastro de una instalacion: instaladores descargados, eventos del registro de
/// Windows (con la cuenta que los lanzo) y programas de arranque automatico.
/// Es la parte que permite saber quien instalo que.
pub fn evidence() -> Result<()> {
    print!("{}", run_or_note(EVIDENCE)?);
    Ok(())
}

/// true si el programa incumple una regla y no esta en la lista blanca.
fn flagged_app(app: &App) -> bool {
    junk::classify(&app.name).is_some() && !junk::kept(&app.name, &app.publisher)
}

/// Inventario completo (registro + Microsoft Store). Vacio fuera de Windows.
pub fn inventory() -> Result<Vec<App>> {
    #[cfg(windows)]
    {
        Ok(parse_inventory(&crate::ps::run(INVENTORY)?))
    }

    #[cfg(not(windows))]
    {
        Ok(Vec::new())
    }
}

/// Interpreta la salida tabulada del script de inventario. Es puro, para poder
/// probarlo en cualquier plataforma.
#[cfg_attr(not(windows), allow(dead_code))]
fn parse_inventory(text: &str) -> Vec<App> {
    text.lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split('\t').collect();
            if f.len() < 10 {
                return None;
            }
            Some(App {
                hive: f[0].to_string(),
                name: f[1].to_string(),
                version: f[2].to_string(),
                publisher: f[3].to_string(),
                installed: f[4].to_string(),
                size_mb: f[5].to_string(),
                location: f[6].to_string(),
                source: f[7].to_string(),
                uninstall: f[8].to_string(),
                who: f[9].to_string(),
            })
        })
        .collect()
}

/// Recorta por caracteres (no por bytes) para no romper los acentos.
fn corta(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        return s.to_string();
    }
    let mut out: String = s.chars().take(n.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// Texto para un campo vacio.
fn vazio(s: &str) -> &str {
    if s.is_empty() {
        "—"
    } else {
        s
    }
}

/// Ultimas `max` desinstalaciones del historial.
pub fn history(max: u32) -> Result<()> {
    #[cfg(windows)]
    {
        let ps = r#"
$h = '__LOG__'
Write-Output '--- Histórico de desinstalações ---'
if (-not (Test-Path $h)) { Write-Output '  Ainda não foi desinstalado nada.'; exit 0 }
Import-Csv $h -Delimiter ';' | Select-Object -Last __MAX__ |
  Format-Table Data, Perfil, Programa, Versao, Metodo, Resultado -AutoSize | Out-String -Width 200
Write-Output "Ficheiro: $h"
"#
        .replace("__LOG__", &q(&history_path()))
        .replace("__MAX__", &max.to_string());
        print!("{}", crate::ps::run(&ps)?);
        Ok(())
    }

    #[cfg(not(windows))]
    {
        let _ = max;
        println!("[info] O histórico de desinstalações só está disponível no Windows.");
        Ok(())
    }
}

/// Lista los miembros del grupo local de Administradores. Un alumno que sea
/// administrador puede saltarse AppLocker y el firewall, asi que no debe haber
/// ninguno.
pub fn admins() -> Result<()> {
    #[cfg(windows)]
    {
        // Get-LocalGroupMember falla con SIDs huerfanos o cuentas de Entra ID;
        // en ese caso se recurre a ADSI. El grupo se busca por SID para no
        // depender del idioma ("Administradores", "Administrators"...).
        let ps = r#"
$members = try {
  Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop |
    ForEach-Object { $_.Name + "  (" + $_.ObjectClass + ", " + $_.PrincipalSource + ")" }
} catch {
  $g = (New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-544').Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]
  ([ADSI]"WinNT://./$g,group").Invoke('Members') |
    ForEach-Object { $_.GetType().InvokeMember('AdsPath', 'GetProperty', $null, $_, $null) }
}
Write-Output "--- Administradores locais ---"
$members | ForEach-Object { "  " + $_ }
Write-Output "[nota] Nenhum aluno deve estar neste grupo: um administrador consegue contornar o AppLocker e o firewall."
"#;
        print!("{}", crate::ps::run(ps)?);
        Ok(())
    }

    #[cfg(not(windows))]
    {
        println!("[info] A lista de administradores locais só está disponível no Windows.");
        Ok(())
    }
}

/// Desinstala un programa no autorizado por nombre. Dry-run salvo `apply`.
///
/// El dry-run tambien busca, para mostrar que coincide y que se haria.
pub fn remove(name: &str, apply: bool) -> Result<()> {
    #[cfg(windows)]
    {
        if apply {
            println!("[ação] A desinstalar '{name}'...");
        } else {
            println!("[simulação] A procurar software que corresponda a: '{name}'");
        }
        print!("{}", crate::ps::run(&uninstall_script(name, apply))?);
        if !apply {
            println!("[simulação] Execute com --aplicar para desinstalar de facto (requer administrador).");
        }
        Ok(())
    }

    #[cfg(not(windows))]
    {
        if !apply {
            println!("[simulação] Seria desinstalado o software que corresponda a: '{name}'");
            println!("[simulação] Execute com --aplicar para desinstalar de facto (requer administrador).");
        } else {
            println!("[info] A desinstalação só está disponível no Windows ('{name}').");
        }
        Ok(())
    }
}

/// Desinstala una entrada del inventario con el mismo script que `remove`:
/// cubre maquina, todos los perfiles y la Store, y lo anota en el historial.
#[cfg(windows)]
fn remove_app(app: &App) -> Result<()> {
    print!("{}", crate::ps::run(&uninstall_script(&app.name, true))?);
    Ok(())
}

/// Fuera de Windows no hay nada que desinstalar (el inventario viene vacio).
#[cfg(not(windows))]
fn remove_app(_app: &App) -> Result<()> {
    Ok(())
}

/// Ejecuta un script de PowerShell, o avisa de que solo existe en Windows.
#[cfg(windows)]
fn run_or_note(script: &str) -> Result<String> {
    crate::ps::run(script)
}

#[cfg(not(windows))]
fn run_or_note(_script: &str) -> Result<String> {
    Ok("[info] Esta operação só está disponível no Windows.\n".to_string())
}

/// Script de inventario: emite una linea por programa, campos separados por
/// tabulador (el orden lo fija `parse_inventory`).
#[cfg(windows)]
const INVENTORY: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'

function Limpa([string] $s) {
  if ($null -eq $s) { return '' }
  return (($s -replace "[`t`r`n]", ' ').Trim())
}

$hives = @(
  @{ Hive = 'HKLM64'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' },
  @{ Hive = 'HKLM32'; Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall' },
  @{ Hive = 'HKCU';   Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' }
)

foreach ($h in $hives) {
  foreach ($k in @(Get-ChildItem $h.Path)) {
    $v = Get-ItemProperty $k.PSPath
    if (-not $v.DisplayName) { continue }

    # Data: InstallDate (AAAAMMDD); se falta, a ultima escrita da chave; e por
    # ultimo a criacao da pasta. Nas chaves HKCU o LastWriteTime vem vazio.
    $data = ''
    if ($v.InstallDate -match '^(\d{4})(\d{2})(\d{2})') {
      $data = "$($Matches[1])-$($Matches[2])-$($Matches[3])"
    }
    if (-not $data -and $k.LastWriteTime) {
      $data = $k.LastWriteTime.ToString('yyyy-MM-dd')
    }
    if (-not $data -and $v.InstallLocation -and (Test-Path -LiteralPath $v.InstallLocation)) {
      $data = (Get-Item -LiteralPath $v.InstallLocation).CreationTime.ToString('yyyy-MM-dd')
    }

    $tam = ''
    if ($v.EstimatedSize) { $tam = [string][math]::Round($v.EstimatedSize / 1024, 1) }

    # HKCU solo lo escribe el utilizador de la sesion; HKLM exige admin.
    $quem = 'todos (admin)'
    if ($h.Hive -eq 'HKCU') { $quem = $env:USERNAME }

    $un = $v.QuietUninstallString
    if (-not $un) { $un = $v.UninstallString }

    @(
      $h.Hive,
      (Limpa $v.DisplayName),
      (Limpa $v.DisplayVersion),
      (Limpa $v.Publisher),
      $data,
      $tam,
      (Limpa $v.InstallLocation),
      (Limpa $v.InstallSource),
      (Limpa $un),
      (Limpa $quem)
    ) -join "`t"
  }
}

# Apps de la Microsoft Store (Spotify, Lively, cursores...). Los componentes
# del sistema viven en C:\Windows; las apps instaladas, en WindowsApps. Se
# excluyen tambien las librerias compartidas y las apps de Microsoft
# (PublisherId 8wekyb3d8bbwe = Windows/Office), que son parte del sistema.
foreach ($a in @(Get-AppxPackage)) {
  if ($a.InstallLocation -like "$env:SystemRoot\*") { continue }
  if ($a.PublisherId -eq '8wekyb3d8bbwe') { continue }
  if ($a.Name -like 'MicrosoftWindows.*' -or $a.Name -like 'windows.*') { continue }
  if ($a.Name -like '*.VCLibs' -or $a.Name -like '*WindowsAppRuntime*' -or $a.Name -like '*WinAppRuntime*') { continue }
  $data = ''
  if ($a.InstallLocation -and (Test-Path -LiteralPath $a.InstallLocation)) {
    $data = (Get-Item -LiteralPath $a.InstallLocation).CreationTime.ToString('yyyy-MM-dd')
  }
  @(
    'APPX',
    (Limpa $a.Name),
    (Limpa $a.Version),
    (Limpa $a.PublisherDisplayName),
    $data,
    '',
    (Limpa $a.InstallLocation),
    'Microsoft Store',
    (Limpa $a.PackageFullName),
    (Limpa $env:USERNAME)
  ) -join "`t"
}
"#;

/// Script que borra los restos: carpetas de datos de las apps de la lista negra
/// y los cursores descargados. No toca nada mas.
fn cleanup_script(apply: bool) -> String {
    let mut s = String::from("$apply = ");
    s.push_str(if apply { "$true" } else { "$false" });
    s.push_str("\n$ErrorActionPreference = 'SilentlyContinue'\n");
    s.push_str(
        r#"$alvos = @(
  "$env:LOCALAPPDATA\Roblox",
  "$env:APPDATA\Spotify",
  "$env:LOCALAPPDATA\Spotify",
  "$env:LOCALAPPDATA\Lively Wallpaper",
  "$env:APPDATA\Lively Wallpaper",
  "$env:APPDATA\RustDesk",
  "$env:LOCALAPPDATA\RustDesk"
)
$alvos += @(Get-ChildItem "$env:LOCALAPPDATA\Packages" -Directory |
  Where-Object { $_.Name -match 'SpotifyAB|LivelyWallpaper|CustomCursors' } |
  ForEach-Object { $_.FullName })

foreach ($a in $alvos) {
  if (Test-Path -LiteralPath $a) {
    Write-Output ("REMOVER=" + $a)
    if ($apply) { Remove-Item -LiteralPath $a -Recurse -Force }
  }
}

# Cursores personalizados que se descargan a Transferencias.
Get-ChildItem (Join-Path $env:USERPROFILE 'Downloads') -File |
  Where-Object { $_.Extension -in '.ani', '.cur' -or $_.Name -match 'cursor' } |
  ForEach-Object {
    Write-Output ("REMOVER=" + $_.FullName)
    if ($apply) { Remove-Item -LiteralPath $_.FullName -Force }
  }
"#,
    );
    s
}

/// Script que devuelve el esquema de punteros al de Windows (los ficheros
/// `*_eoa.cur` del perfil son los predefinidos de Windows 10/11).
fn cursor_script(apply: bool) -> String {
    let mut s = String::from("$apply = ");
    s.push_str(if apply { "$true" } else { "$false" });
    s.push_str("\n$ErrorActionPreference = 'SilentlyContinue'\n");
    s.push_str(
        r#"$k = 'HKCU:\Control Panel\Cursors'
$base = Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\Cursors'
$mapa = @{
  'Arrow'       = 'arrow_eoa.cur'
  'Help'        = 'helpsel_eoa.cur'
  'AppStarting' = 'busy_eoa.cur'
  'Wait'        = 'wait_eoa.cur'
  'Crosshair'   = 'cross_eoa.cur'
  'IBeam'       = 'ibeam_eoa.cur'
  'NWPen'       = 'pen_eoa.cur'
  'No'          = 'unavail_eoa.cur'
  'SizeNS'      = 'ns_eoa.cur'
  'SizeWE'      = 'ew_eoa.cur'
  'SizeNWSE'    = 'nwse_eoa.cur'
  'SizeNESW'    = 'nesw_eoa.cur'
  'SizeAll'     = 'move_eoa.cur'
  'UpArrow'     = 'up_eoa.cur'
  'Hand'        = 'link_eoa.cur'
  'Pin'         = 'pin_eoa.cur'
  'Person'      = 'person_eoa.cur'
}
$alterado = $false
foreach ($n in $mapa.Keys) {
  $atual = (Get-ItemProperty $k).$n
  if ($atual -and $atual -notlike (Join-Path $base '*')) { $alterado = $true }
}
if (-not $alterado) {
  Write-Output '[ok] O cursor já é o predefinido do Windows.'
  exit 0
}
# Sin los ficheros del esquema no se toca nada: el puntero quedaria invisible.
if (-not (Test-Path (Join-Path $base 'arrow_eoa.cur'))) {
  Write-Output '[aviso] Não se encontraram os cursores do Windows; não se altera nada.'
  exit 0
}
Write-Output 'CURSOR=Windows Aero (predefinido)'
if (-not $apply) { exit 0 }
Set-ItemProperty -Path $k -Name '(default)' -Value 'Windows Aero'
foreach ($n in $mapa.Keys) {
  Set-ItemProperty -Path $k -Name $n -Value (Join-Path $base $mapa[$n])
}
# Aplica sem terminar a sessao.
rundll32.exe user32.dll,UpdatePerUserSystemParameters
Write-Output '  [ok] cursor reposto'
"#,
    );
    s
}

/// Rastro de instalacion: instaladores, eventos del sistema y arranque.
const EVIDENCE: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'

Write-Output '-- Instaladores descarregados (Transferências) --'
Get-ChildItem (Join-Path $env:USERPROFILE 'Downloads') -File |
  Where-Object { $_.Name -match 'roblox|spotify|lively|cursor|rustdesk|anydesk|teamviewer|steam|epic|tlauncher' } |
  Sort-Object CreationTime |
  ForEach-Object { "  {0:yyyy-MM-dd HH:mm}  {1}" -f $_.CreationTime, $_.Name }

Write-Output ''
Write-Output '-- Instalações registadas pelo Windows (quem) --'
Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'MsiInstaller'; Id = 11707 } -MaxEvents 60 |
  ForEach-Object {
    $linha = ($_.Message -split "`r?`n")[0]
    $utilizador = ''
    try {
      if ($_.UserId) {
        $utilizador = (New-Object Security.Principal.SecurityIdentifier($_.UserId)).Translate([Security.Principal.NTAccount]).Value
      }
    } catch { }
    "  {0:yyyy-MM-dd HH:mm}  {1}  {2}" -f $_.TimeCreated, $utilizador, $linha
  }

Write-Output ''
Write-Output '-- Arranque automático --'
foreach ($rk in @(
  'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
)) {
  $p = Get-ItemProperty $rk
  if (-not $p) { continue }
  $p.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
    "  {0}  {1} = {2}" -f $rk.Split('\')[0], $_.Name, $_.Value
  }
}
"#;

/// Script que localiza los programas cuyo nombre contiene `name` (maquina,
/// todos los perfiles y Store) y, si `apply`, los quita y lo anota en el
/// historial. No encontrar nada no es un error (el equipo ya esta limpio); un
/// desinstalador que falla si lo es.
#[cfg(windows)]
fn uninstall_script(name: &str, apply: bool) -> String {
    UNINSTALL_PS
        .replace("__NAME__", &q(name))
        .replace("__APPLY__", if apply { "true" } else { "false" })
        .replace("__LOG__", &q(&history_path()))
}

#[cfg(windows)]
const UNINSTALL_PS: &str = r#"
$name = '__NAME__'
$apply = $__APPLY__
$historico = '__LOG__'
$uninst = 'Software\Microsoft\Windows\CurrentVersion\Uninstall'
$script:failed = $false
$script:found = 0

function Historico($programa, $versao, $perfil, $metodo, $resultado) {
  if (-not $apply -or -not $historico) { return }
  try {
    New-Item -ItemType Directory -Force -Path (Split-Path $historico) | Out-Null
    if (-not (Test-Path $historico)) {
      'Data;Computador;Perfil;Programa;Versao;Metodo;Resultado' | Set-Content $historico -Encoding UTF8
    }
    $campos = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $env:COMPUTERNAME, $perfil, $programa, $versao, $metodo, $resultado
    ($campos | ForEach-Object { "$_" -replace ';', ',' }) -join ';' | Add-Content $historico -Encoding UTF8
  } catch { Write-Output "  [aviso] Não foi possível escrever no histórico: $_" }
}

# Ejecuta un desinstalador con un limite de 5 minutos; devuelve el codigo.
function Executar($exe, $argList) {
  $p = Start-Process -FilePath $exe -ArgumentList $argList -PassThru -NoNewWindow
  $null = $p.Handle   # sin esto, ExitCode sale vacio en PowerShell 5.1
  if (-not $p.WaitForExit(300000)) { $p.Kill(); return -1 }
  return $p.ExitCode
}

# Carpeta de un programa por usuario: la primera por debajo de AppData\Local\Programs,
# AppData\Local o AppData\Roaming. Nunca devuelve esas raices ni carpetas comunes.
function Pasta-App($app, $perfilDir) {
  $cands = @()
  if ($app.InstallLocation) { $cands += $app.InstallLocation.Trim([char[]]@('"', ' ', '\')) }
  foreach ($c in $app.UninstallString, $app.DisplayIcon) {
    if ($c -and $c -match '^\s*"?([^"]+?\.exe)') { $cands += Split-Path $Matches[1] }
  }
  $raizes = 'AppData\Local\Programs', 'AppData\Local', 'AppData\Roaming' | ForEach-Object { Join-Path $perfilDir $_ }
  foreach ($c in $cands) {
    foreach ($r in $raizes) {
      if ($c.StartsWith($r + '\', [StringComparison]::OrdinalIgnoreCase)) {
        $sub = $c.Substring($r.Length + 1).Split('\')[0]
        if ($sub -and $sub -notin 'Programs', 'Temp', 'Microsoft', 'Packages', 'Google', 'Mozilla') {
          return Join-Path $r $sub
        }
        break
      }
    }
  }
  return $null
}

# --- Instalaciones de maquina ---------------------------------------------
$maquina = @(Get-ItemProperty "HKLM:\SOFTWARE\$uninst\*", "HKLM:\SOFTWARE\WOW6432Node\$uninst\*" -ErrorAction SilentlyContinue |
  Where-Object { $_.DisplayName -like "*$name*" })
foreach ($app in $maquina) {
  $script:found++
  Write-Output ("ALVO=" + $app.DisplayName + " " + $app.DisplayVersion)
  $cmd = $app.QuietUninstallString
  if (-not $cmd) { $cmd = $app.UninstallString }
  if (-not $cmd) { Write-Output '  SEM_UNINSTALL_STRING'; $script:failed = $true; continue }
  # MSI registra "MsiExec.exe /I{GUID}", que abre el asistente de modificacion:
  # se cambia por /x silencioso. Inno Setup (unins000.exe) necesita /VERYSILENT.
  if ($cmd -match 'msiexec' -and $cmd -match '(\{[0-9A-Fa-f-]{36}\})') {
    $exe = 'msiexec.exe'; $argList = "/x $($Matches[1]) /qn /norestart"
  } else {
    if ($cmd -match 'unins\d+\.exe' -and $cmd -notmatch '/VERYSILENT') { $cmd += ' /VERYSILENT /SUPPRESSMSGBOXES /NORESTART' }
    # NSIS (Steam, entre otros): uninstall.exe o uninst.exe se callan con /S.
    if ($cmd -match '\\uninst(all)?\.exe"?\s*$') { $cmd += ' /S' }
    # Comillas exteriores para que cmd /c no recorte las de la ruta.
    $exe = 'cmd.exe'; $argList = '/c "' + $cmd + '"'
  }
  Write-Output ("  CMD=" + $exe + " " + $argList)
  if (-not $apply) { continue }
  $code = Executar $exe $argList
  Write-Output ("  SAIDA=" + $code)
  # 1605 = ya no estaba instalado, 3010 = OK pendiente de reinicio.
  if ($code -in 0, 1605, 3010) {
    Historico $app.DisplayName $app.DisplayVersion 'computador' 'desinstalador' 'ok'
  } else {
    $script:failed = $true
    Historico $app.DisplayName $app.DisplayVersion 'computador' 'desinstalador' "falhou ($code)"
  }
}

# --- Instalaciones por usuario, en todos los perfiles ----------------------
# Solo perfiles con la sesion abierta (su hive ya esta en HKEY_USERS). Cargar
# el NTUSER.DAT de los demas con reg load congelaba el inicio de sesion.
$perfis = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' |
  Where-Object { $_.PSChildName -like 'S-1-5-21-*' }
foreach ($pf in $perfis) {
  $sid = $pf.PSChildName
  $perfilDir = (Get-ItemProperty $pf.PSPath).ProfileImagePath
  $perfil = Split-Path $perfilDir -Leaf
  $raiz = "Registry::HKEY_USERS\$sid"
  if (-not (Test-Path $raiz)) { continue }
  $apps = @(Get-ItemProperty "$raiz\$uninst\*" -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like "*$name*" })
  foreach ($app in $apps) {
    $script:found++
    Write-Output ("ALVO=" + $app.DisplayName + " " + $app.DisplayVersion + "  (perfil " + $perfil + ")")
    $pasta = Pasta-App $app $perfilDir
    if (-not $pasta) {
      Write-Output '  SEM_PASTA: não se encontrou a pasta do programa em AppData.'
      $script:failed = $true
      Historico $app.DisplayName $app.DisplayVersion $perfil 'apagar pasta' 'falhou (sem pasta)'
      continue
    }
    Write-Output ("  APAGAR=" + $pasta)
    if (-not $apply) { continue }
    Get-Process -ErrorAction SilentlyContinue |
      Where-Object { $_.Path -and $_.Path.StartsWith($pasta + '\', [StringComparison]::OrdinalIgnoreCase) } |
      Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 500
    Remove-Item -LiteralPath $pasta -Recurse -Force -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $pasta) {
      Write-Output '  [erro] A pasta não pôde ser apagada por completo.'
      $script:failed = $true
      Historico $app.DisplayName $app.DisplayVersion $perfil 'apagar pasta' 'falhou'
    } else {
      Remove-Item -LiteralPath $app.PSPath -Recurse -Force -ErrorAction SilentlyContinue
      Write-Output '  [ok] Removido.'
      Historico $app.DisplayName $app.DisplayVersion $perfil 'apagar pasta' 'ok'
    }
  }
}

# --- Apps de la Microsoft Store --------------------------------------------
$appxName = $name -replace '\s', ''
$pkgs = @(Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*$appxName*" -and $_.Name -notlike 'Microsoft.*' -and $_.Name -notlike 'MicrosoftWindows.*' -and -not $_.IsFramework -and $_.SignatureKind -ne 'System' })
foreach ($p in $pkgs) {
  $script:found++
  Write-Output ("ALVO=" + $p.Name + " " + $p.Version + "  (Microsoft Store)")
  if (-not $apply) { continue }
  try {
    Remove-AppxPackage -Package $p.PackageFullName -AllUsers -ErrorAction Stop
    Write-Output '  [ok] Removido.'
    Historico $p.Name $p.Version 'todos' 'Microsoft Store' 'ok'
  } catch {
    Write-Output "  [erro] $_"
    $script:failed = $true
    Historico $p.Name $p.Version 'todos' 'Microsoft Store' 'falhou'
  }
}

# --- Ultimo recurso: winget -------------------------------------------------
if ($script:found -eq 0) {
  if ($apply -and (Get-Command winget -ErrorAction SilentlyContinue)) {
    & winget uninstall --name $name --silent --accept-source-agreements --disable-interactivity 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
      Write-Output "[ok] '$name' desinstalado através do winget."
      Historico $name '' 'computador' 'winget' 'ok'
      exit 0
    }
  }
  Write-Output "NAO_ENCONTRADO: nenhum programa corresponde a '$name'."
  exit 0
}
if ($script:failed) { exit 1 }
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interpreta_el_inventario_tabulado() {
        let texto = "HKCU\tRoblox Player for Aluno(a)\t1.0\tRoblox Corporation\t2026-10-22\t120.5\tC:\\Roblox\tC:\\Descargas\\setup.exe\t\"C:\\Roblox\\Installer.exe\" -uninstall\tAluno(a)\nAPPX\tSpotifyAB.SpotifyMusic\t1.306\tSpotify AB\t2026-10-27\t\tC:\\Apps\\Spotify\tMicrosoft Store\tSpotifyAB.SpotifyMusic_1.0_x64__zpd\tAluno(a)\n";
        let apps = parse_inventory(texto);
        assert_eq!(apps.len(), 2);
        assert_eq!(apps[0].hive, "HKCU");
        assert_eq!(apps[0].name, "Roblox Player for Aluno(a)");
        assert_eq!(apps[0].installed, "2026-10-22");
        assert_eq!(apps[0].who, "Aluno(a)");
        assert_eq!(apps[1].hive, "APPX");
        assert_eq!(apps[1].source, "Microsoft Store");
    }

    #[test]
    fn ignora_lineas_incompletas() {
        assert!(parse_inventory("basura\n\nHKCU\tsolo-dos-campos").is_empty());
    }

    #[test]
    fn recorta_sin_romper_acentos() {
        assert_eq!(corta("Roblox", 10), "Roblox");
        assert_eq!(corta("Controlador gráfico", 6), "Contr…");
    }

    #[test]
    fn la_lista_por_defecto_incluye_las_apps_pedidas() {
        for app in [
            "Lively Wallpaper",
            "Custom Cursor",
            "Roblox",
            "Spotify",
            "Steam",
            "Riot Client",
        ] {
            assert!(super::APPS.contains(&app), "falta {app}");
        }
    }
}
