# HANDOFF — aegn-agent

Documento para quien continúe el proyecto (humano o un modelo más capaz que
haga el diseño fino). Resume qué hay, qué es sólido y qué queda por decidir.

## Qué es esto

Agente interno de administración de los PCs **propiedad de la Escola AEGN**.
Objetivo: que los equipos se usen como material de estudio — evitar que los
alumnos instalen juegos/instaladores en carpetas de usuario (donde no hace falta
admin) y desinstalar software no autorizado. Es gestión de parque informático
estándar, con mecanismos nativos y auditables de Windows. **No hay dimensión
ofensiva de ciberseguridad**: nada de sigilo, exfiltración ni evasión; todo es
transparente y reversible.

## Estado actual (v0.3.0)

```
src/
  main.rs      CLI (clap) en portugués, con alias de la v0.1 en inglés
  auth.rs      Contraseña de administración (PBKDF2 en HKLM; por defecto "admin")
  tui.rs       Menú TUI: salida en vivo; en modo real pide la contraseña
  process.rs   Orquesta la rutina (inventario → desinstalar → limpieza → AppLocker → firewall)
  audit.rs     Inventario con fecha/usuario/origen, detalle, rastro y limpieza
  junk.rs      Lista negra (reglas) y lista blanca (sistema): lógica pura con tests
  policy.rs    AppLocker Exe/Script/Msi, modo auditoría, eventos, revert
  firewall.rs  Bloqueo saliente de RustDesk/AnyDesk/TeamViewer
  schedule.rs  Tarea SYSTEM diaria (solo si aegn.exe está en Program Files)
  ps.rs        Ejecuta PowerShell (solo Windows)
installer/     MSI (WiX 5), instalar.ps1/.cmd, desinstalar.cmd, notas del release
.github/workflows/release.yml   Compila en Windows y publica el release al subir vX.Y.Z
```

Invariantes que conviene NO romper:

- **Simulación por defecto.** Toda acción que cambia el equipo exige
  `--aplicar` y la contraseña del agente (SYSTEM no la pide).
- **Textos de usuario en portugués (pt-PT)**; comentarios de código en español.
- **Código Windows tras `#[cfg(windows)]`**, para que compile en Linux.
- **La lista blanca manda**: `junk::kept()` protege sistema, drivers, Tailscale
  y Git aunque una regla de `junk::RULES` coincida.

La lógica real de Windows aún **no** se ha probado en una máquina Windows con
admin; el workflow solo compila y ejecuta los tests en Windows.

## Decisiones ya tomadas (y por qué)

| Tema | Decisión | Motivo |
|---|---|---|
| Restricción de ejecución | AppLocker (reglas de ruta) | Método soportado por Microsoft, auditable, reversible. |
| Desinstalación | winget primero, luego `UninstallString` | Cubre software moderno y legado. |
| Apps de la Store | `Remove-AppxPackage` | Las apps de la Store no están en el registro Uninstall y winget no las quita. |
| Lista negra | Reglas en `junk.rs` (código, con tests) | Auditable y sin ficheros de configuración que un alumno pueda editar. |
| Atribución | Metadatos del propio Windows | `InstallDate`, `HKCU` vs `HKLM`, `InstallSource` y eventos `MsiInstaller` con la cuenta. |
| Contraseña | Hash PBKDF2 en HKLM | Solo admins escriben; protege de uso casual, no de un admin decidido. |
| Instalación | MSI en `C:\Program Files\AEGN` + PATH del sistema | La tarea SYSTEM exige una ruta no escribible por usuarios. |
| Compilación | GitHub Actions `windows-latest` | En Linux no hay linker de Windows. |

## Pendiente (orden sugerido)

1. **Probar en Windows real con admin**: instalador, contraseña, AppLocker,
   AppIDSvc, firewall y tarea.
2. **Lista negra configurable** por centro (`aegn.toml`): hoy es código en
   `junk.rs`; falta poder añadir reglas sin recompilar.
3. **Fallback SRP** para Windows Home (sin AppLocker).
4. **Informe por ejecución** en disco.

## Avisos para el despliegue (no técnico)

Acompañar la instalación de la política de uso aceptable de la escuela, para que
alumnos y familias sepan que los equipos están gestionados. Son máquinas de la
escuela; el agente no toca equipos personales.
