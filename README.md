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

| Comando | Qué hace |
|---|---|
| `aegn` / `aegn menu` | Menú interactivo (TUI) con banner ASCII. |
| `aegn audit list` | Inventario de software instalado (claves Uninstall del registro). |
| `aegn audit remove <nombre>` | Desinstala software no autorizado (winget + fallback). Dry-run sin `--apply`. |
| `aegn policy status` | Estado de las políticas de ejecución (AppLocker + AppIDSvc). |
| `aegn policy enforce` | Bloquea ejecución de `.exe` en `AppData\Local` y `Downloads`. Dry-run sin `--apply`. |
| `aegn policy revert` | Revierte las reglas aplicadas por el agente. Dry-run sin `--apply`. |
| `aegn gh whoami` | Verifica el token leyendo `GITHUB_TOKEN`. |

## Seguridad y diseño

- **Dry-run por defecto**: toda acción destructiva (`remove`, `enforce`,
  `revert`) solo simula hasta que se pasa `--apply`.
- **Credenciales**: el PAT de GitHub se lee exclusivamente de la variable de
  entorno `GITHUB_TOKEN`; nunca se acepta por argumento ni se imprime.
- **Privilegios**: las operaciones de sistema requieren consola de
  administrador en Windows.
- **Restricción de ejecución**: se implementa con reglas de ruta de AppLocker,
  el método soportado por Microsoft para control de aplicaciones.

## Compilar

```bash
cargo build --release
```

El binario queda en `target/release/aegn`.

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
