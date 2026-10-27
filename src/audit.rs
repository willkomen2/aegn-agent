//! Auditoria y remocion de software no autorizado.
//!
//! En Windows se apoya en mecanismos legitimos:
//! - Inventario: claves de desinstalacion del registro (`...\Uninstall`), la
//!   misma fuente que usa "Programas y caracteristicas", de la maquina y de los
//!   perfiles con sesion abierta, mas las apps de la Microsoft Store (Appx).
//! - Desinstalacion, para cada coincidencia por nombre:
//!   - instalacion de maquina: su `UninstallString` en modo silencioso;
//!   - instalacion por usuario (Roblox, Spotify...): se recorren todos los
//!     perfiles (cargando el NTUSER.DAT de los que no tienen sesion) y se borra
//!     la carpeta de AppData del programa y su clave, porque su desinstalador
//!     correria en el perfil del administrador y no en el del alumno;
//!   - app de la Store: `Remove-AppxPackage -AllUsers`;
//!   - si nada coincide, `winget uninstall` como ultimo recurso.
//! - Historial: cada desinstalacion real se anota en `logs\desinstalacoes.csv`
//!   junto al ejecutable, con fecha, perfil y version.
//!
//! Toda remocion es dry-run salvo que se pase `apply = true`.

use anyhow::Result;

/// Programas no autorizados que el proceso desinstala por defecto, ademas de
/// RustDesk y OpenCode (que tienen opcion propia). Se buscan por nombre: el
/// texto debe aparecer en el nombre del programa.
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

/// Lista el software instalado, marca el no autorizado y muestra las ultimas
/// desinstalaciones.
pub fn list() -> Result<()> {
    #[cfg(windows)]
    {
        let names = APPS
            .iter()
            .chain(["RustDesk", "OpenCode"].iter())
            .map(|n| format!("'{}'", q(n)))
            .collect::<Vec<_>>()
            .join(",");
        // HKEY_USERS\* cubre los perfiles con sesion abierta (alumnos incluidos).
        let ps = r#"
$paths = @(
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
  'Registry::HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$apps = @(Get-ItemProperty $paths -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } |
  Sort-Object DisplayName -Unique)
$apps | Select-Object DisplayName, DisplayVersion, Publisher | Format-Table -AutoSize | Out-String -Width 200
$proibidos = @(__NAMES__)
$appx = @(Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue)
$achados = foreach ($n in $proibidos) {
  $apps | Where-Object { $_.DisplayName -like "*$n*" } | ForEach-Object { "  " + $_.DisplayName + " " + $_.DisplayVersion }
  $appx | Where-Object { $_.Name -like ("*" + ($n -replace '\s','') + "*") } | ForEach-Object { "  " + $_.Name + " " + $_.Version + "  (Microsoft Store)" }
}
Write-Output '--- Software não autorizado encontrado ---'
if ($achados) { $achados | Sort-Object -Unique } else { Write-Output '  [ok] Nenhum.' }
Write-Output '[nota] Os perfis sem sessão aberta não aparecem aqui; o processo também os limpa.'
"#
        .replace("__NAMES__", &names);
        print!("{}", crate::ps::run(&ps)?);
        println!();
        history(10)
    }

    #[cfg(not(windows))]
    {
        println!("[info] O inventário de software só está disponível no Windows.");
        println!("[info] No computador executaria: Get-ItemProperty sobre as chaves Uninstall do registo.");
        Ok(())
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
$carregados = @()
try {
  $perfis = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' |
    Where-Object { $_.PSChildName -like 'S-1-5-21-*' }
  foreach ($pf in $perfis) {
    $sid = $pf.PSChildName
    $perfilDir = (Get-ItemProperty $pf.PSPath).ProfileImagePath
    $perfil = Split-Path $perfilDir -Leaf
    $raiz = "Registry::HKEY_USERS\$sid"
    if (-not (Test-Path $raiz)) {
      # Perfil sin sesion abierta: se carga su NTUSER.DAT el tiempo justo.
      $dat = Join-Path $perfilDir 'NTUSER.DAT'
      if (-not (Test-Path $dat)) { continue }
      $tmp = 'AEGN_' + $sid
      & reg.exe load "HKU\$tmp" "$dat" 2>&1 | Out-Null
      if ($LASTEXITCODE -ne 0) { Write-Output "  [aviso] Não foi possível abrir o perfil $perfil."; continue }
      $carregados += $tmp
      $raiz = "Registry::HKEY_USERS\$tmp"
    }
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
} finally {
  # Sin soltar las referencias, reg unload falla con "acceso denegado".
  [gc]::Collect(); [gc]::WaitForPendingFinalizers()
  foreach ($h in $carregados) { & reg.exe unload "HKU\$h" 2>&1 | Out-Null }
}

# --- Apps de la Microsoft Store --------------------------------------------
$appxName = $name -replace '\s', ''
$pkgs = @(Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*$appxName*" })
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
