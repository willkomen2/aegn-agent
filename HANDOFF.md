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

## Estado actual (v0.1.0) — base funcional

```
src/
  main.rs      CLI (clap): menu | run | audit | policy | gh
  tui.rs       Menú TUI: banner ASCII + toggles + "Iniciar proceso"
  process.rs   Orquesta la rutina (inventario → desinstalar → políticas)
  audit.rs     Inventario (registro) y desinstalar (winget + UninstallString)
  policy.rs    AppLocker: deny en AppData\Local y Downloads; status; revert
  github.rs    Lee GITHUB_TOKEN del entorno, valida contra /user
```

Invariantes que conviene NO romper:

- **Dry-run por defecto.** Toda acción destructiva exige `--apply` (CLI) o el
  toggle "APLICAR DE VERDAD" (menú). Mantener esto.
- **Credenciales solo por entorno** (`GITHUB_TOKEN`), nunca por argumento ni en
  logs.
- **Código Windows tras `#[cfg(windows)]`**, para que compile en el equipo de
  desarrollo (Linux) sin ejecutar PowerShell.

Verificado: compila sin warnings; `aegn --help`, `aegn run --simple` (dry-run) y
los dry-run de `policy`/`audit` imprimen lo esperado. La lógica real de Windows
aún **no** se ha probado en una máquina Windows con admin.

## Decisiones ya tomadas (y por qué)

| Tema | Decisión | Motivo |
|---|---|---|
| Restricción de ejecución | AppLocker (reglas de ruta) | Método soportado por Microsoft, auditable, reversible. |
| Desinstalación | winget primero, luego `UninstallString` | Cubre software moderno y legado. |
| Inventario | Claves `Uninstall` del registro | Misma fuente que "Programas y características". |
| TUI | ratatui + crossterm + figlet-rs | ASCII art + interfaz robusta. |

## Lo que debería diseñar quien siga (orden sugerido)

1. **Probar en Windows real con admin.** Validar winget silencioso, AppLocker y
   que `AppIDSvc` arranca. Ajustar los scripts PowerShell según la salida real.
2. **Volver al menú tras una acción.** Hoy ejecutar una opción cierra la TUI;
   idealmente debería re-entrar al menú (restaurar → ejecutar → re-init).
3. **Lista de software no autorizado configurable.** Ahora RustDesk/OpenCode
   están fijos en `process.rs`. Moverlo a un archivo de configuración
   (`aegn.toml` o JSON) con nombres + IDs de winget, editable por el admin.
4. **Logging/reporte.** Guardar un informe de cada ejecución (qué se encontró,
   qué se quitó) en disco o enviarlo a un repo/endpoint central.
5. **AppLocker vs WDAC vs SRP.** AppLocker necesita Windows Pro/Enterprise.
   Evaluar fallback (Software Restriction Policies por registro) para ediciones
   que no lo soporten.
6. **Despliegue.** Tarea programada / servicio que ejecute `aegn run --apply` en
   arranque o periódicamente; instalación en PATH ya documentada en el README.
7. **GitHub.** Completar `github.rs` con `repo create` y push del proyecto vía
   API usando el PAT.
8. **Tests.** Al menos unitarios de la generación de XML de AppLocker y del
   parseo de config.

## Avisos para el despliegue (no técnico)

Acompañar la instalación de la política de uso aceptable de la escuela, para que
alumnos y familias sepan que los equipos están gestionados. Son máquinas de la
escuela; el agente no toca equipos personales.
