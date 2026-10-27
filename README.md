# aegn-agent

Agente interno de administración y seguridad de endpoints para el parque
informático de la **Escola AEGN**. Herramienta de línea de comandos (CLI/TUI) en
Rust para que el administrador de sistemas mantenga las máquinas de la escuela
como material de estudio.

> [!NOTE]
> Herramienta de administración de equipos **propiedad de la escuela**. Usa
> mecanismos nativos y auditables de Windows (winget, AppLocker, registro). No
> es software oculto: las acciones son transparentes y reversibles, y el
> despliegue debe acompañarse de la política de uso aceptable de la escuela.

## Funciones

Todo lo que cambia el equipo es **dry-run** hasta que se pasa `--apply`.

| Comando | Qué hace |
|---|---|
| `aegn` / `aegn menu` | Menú interactivo (TUI): salida en vivo, confirmación en modo real. |
| `aegn run` | Proceso completo: inventario, administradores, desinstalación, AppLocker y firewall. Flags `--simple`, `--no-rustdesk`, `--no-opencode`, `--no-policies`, `--audit-only`, `--no-firewall`, `--apply`. |
| `aegn status` | Estado de AppLocker/AppIDSvc, reglas de firewall y tarea programada. |
| `aegn revert` | Deshace todo lo aplicado por el agente (no reinstala software). |
| `aegn audit list` | Inventario de software instalado (claves Uninstall del registro). |
| `aegn audit admins` | Miembros del grupo local de Administradores. |
| `aegn audit remove <nombre>` | Desinstala software no autorizado (winget, con fallback a la UninstallString). |
| `aegn policy enforce [--audit-only]` | Política AppLocker (Exe, Script y MSI). |
| `aegn policy events [--max N]` | Últimos bloqueos y avisos de auditoría de AppLocker. |
| `aegn policy status` / `revert` | Estado / retirada de las reglas AppLocker AEGN. |
| `aegn firewall status` / `enforce` / `revert` | Bloqueo saliente de RustDesk, AnyDesk y TeamViewer. |
| `aegn schedule install [--audit-only]` / `status` / `remove` | Tarea SYSTEM que reaplica el proceso al arrancar y a diario. |
| `aegn gh whoami` | Verifica el token leyendo `GITHUB_TOKEN`. |

## Despliegue recomendado en un aula

1. Copiar `aegn.exe` a `C:\Program Files\aegn\` (fuera de las carpetas
   bloqueadas y no modificable por alumnos).
2. `aegn run --audit-only --apply`: AppLocker solo registra, no bloquea.
3. Usar los equipos unos días y revisar `aegn policy events`: cada línea
   `AUDIT` es algo que se bloquearía (Teams, OneDrive o VS Code instalados por
   usuario, scripts de inicio de sesión…).
4. `aegn run --apply`: activa el bloqueo.
5. `aegn schedule install --apply`: el equipo se corrige solo cada día.
   Log en `C:\Program Files\aegn\logs\aegn.log`.

## Protecciones

- **AppLocker** (Exe, Script y MSI): solo se ejecuta lo que está en `%WINDIR%`
  o `%PROGRAMFILES%` (MSI: `%WINDIR%\Installer`); los administradores pueden
  todo. Así quedan bloqueados `.exe`, `.ps1/.bat/.cmd/.vbs/.js` y `.msi` desde
  Descargas, Escritorio, AppData, Documentos o un USB. AppData\Local y
  Downloads llevan además un Deny explícito que aplica **también a los
  administradores**.
- **Firewall**: bloqueo saliente de los puertos de RustDesk (21114-21119),
  AnyDesk (6568) y TeamViewer (5938). AnyDesk y TeamViewer pueden salir por
  443; para cortarlos del todo hace falta filtrado por dominio (proxy o DNS).
- **Administradores locales**: el inventario los lista. Un alumno que sea
  administrador puede saltarse todo lo anterior.
- **Tarea programada**: corre como SYSTEM, así que solo se instala si
  `aegn.exe` está dentro de Program Files; si un usuario pudiera sustituir el
  ejecutable, sería una escalada de privilegios.

## Seguridad y diseño

- **Dry-run por defecto**: nada cambia el equipo sin `--apply`.
- **Reversible**: AppLocker y firewall solo tocan sus reglas propias
  (`AEGN-Deny-UserFolders`, grupo `AEGN-RemoteAccess`); el resto de la
  política local se conserva. `aegn revert --apply` lo deshace todo.
- **Credenciales**: el PAT de GitHub se lee exclusivamente de la variable de
  entorno `GITHUB_TOKEN`; nunca se acepta por argumento ni se imprime.
- **Privilegios**: las operaciones de sistema requieren consola de
  administrador en Windows.
- **Ediciones**: AppLocker solo actúa en Windows Pro/Enterprise/Education.

## Compilar

```bash
cargo build --release
```

El binario queda en `target/release/aegn`.

Desde Linux se puede comprobar que el código de Windows compila (sin enlazar):

```bash
scripts/check-windows.sh          # cargo check
scripts/check-windows.sh clippy   # cargo clippy
```

## Instalar en el PATH (Windows)

Copia `aegn.exe` a una carpeta ya incluida en el PATH, o añade su carpeta:

```powershell
# Como administrador, instalar para toda la máquina:
Copy-Item .\target\release\aegn.exe 'C:\Program Files\AEGN\aegn.exe'
[Environment]::SetEnvironmentVariable(
  'Path',
  [Environment]::GetEnvironmentVariable('Path','Machine') + ';C:\Program Files\AEGN',
  'Machine')
```

Abre una consola nueva y `aegn --help` debería funcionar desde cualquier ruta.

## Uso de la API de GitHub

```powershell
$env:GITHUB_TOKEN = '<tu_PAT>'   # token con scope repo
aegn gh whoami
```
