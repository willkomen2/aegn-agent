# AEGN Security

Sistema de segurança dos computadores da **Escola AEGN**. É uma ferramenta de
linha de comandos com menu interativo (CLI/TUI), escrita em Rust, para que o
administrador de sistemas mantenha os computadores da escola como material de
estudo.

> [!NOTE]
> Ferramenta de administração de computadores **propriedade da escola**. Usa
> mecanismos nativos e auditáveis do Windows (winget, AppLocker, Firewall do
> Windows, Agendador de Tarefas). Não é software oculto: as ações são
> transparentes e reversíveis, e a implantação deve acompanhar a política de
> utilização aceitável da escola.

## Instalação

Descarregue o `AEGN-Security-<versão>-windows.zip` da página de
[releases](../../releases), extraia-o e:

1. Clique com o botão direito em **`instalar.cmd`** → **Executar como administrador**.
2. Defina a senha de administração do AEGN (Enter = `admin`).

O instalador:

- instala o `aegn.exe` em `C:\Program Files\AEGN` (só os administradores
  escrevem lá, o que a tarefa diária exige);
- adiciona essa pasta ao **PATH do sistema**: em qualquer consola nova basta
  escrever `aegn`;
- numa atualização, pede primeiro a senha atual;
- regista a tarefa **`AEGN-Atualizar`**, que mantém o AEGN atualizado sozinho
  (ver [Atualização automática](#atualização-automática)).

Para desinstalar: **`desinstalar.cmd`** como administrador. Pede a senha e
pergunta se deve reverter as proteções antes de remover o programa.

Implantação em massa (GPO, Intune): o MSI instala-se sem interação com
`msiexec /i AEGN-Security-<versão>-x64.msi /qn`. A senha fica `admin` até
alguém a alterar com `aegn senha alterar`.

## Senha de administração

Tudo o que altera o computador (`--aplicar`) pede a senha do AEGN, além da
consola de administrador. Por defeito é **`admin`**.

```powershell
aegn senha alterar     # pede a atual e a nova
aegn senha estado      # avisa se ainda é a de defeito
```

- Guarda-se apenas o hash (PBKDF2-HMAC-SHA256 com sal) em
  `HKLM\SOFTWARE\AEGN\Seguranca`.
- A tarefa diária corre como SYSTEM e não precisa da senha.
- Em scripts, a senha pode passar-se na variável `AEGN_SENHA`.
- Limite: um administrador do Windows que apague essa chave volta à senha
  `admin`. A senha protege do uso casual ou acidental, não de um
  administrador decidido. O essencial continua a ser que **nenhum aluno seja
  administrador**.

## Atualização automática

A partir da versão 0.3.0, cada computador atualiza-se sozinho a partir dos
[releases](../../releases) deste repositório, **sem UAC nem senha**:

- o MSI instala o `atualizar.ps1` em `C:\Program Files\AEGN` e regista a
  tarefa `AEGN-Atualizar`, que corre como **SYSTEM** 5 minutos depois do
  arranque e todos os dias entre as 13:00 e as 14:00 (o atraso aleatório evita
  que uma sala inteira descarregue ao mesmo tempo);
- se o último release tiver um MSI mais recente, descarrega-o, confirma o
  SHA-256 com o `SHA256SUMS.txt` do release e instala-o com `msiexec /qn`;
- a senha, a tarefa diária e as proteções mantêm-se na atualização.

```powershell
aegn atualizar             # compara a versão instalada com o último release
aegn atualizar --aplicar   # atualiza já (qualquer utilizador, sem administrador)
aegn atualizar estado      # estado da tarefa e registo
```

O registo fica em `C:\Program Files\AEGN\logs\atualizacao.log`. Para
publicar uma versão nova basta subir a etiqueta `vX.Y.Z` (ver
[Compilar](#compilar)): os computadores apanham-na na execução seguinte.

> [!IMPORTANT]
> - Os computadores descarregam sem credenciais, por isso **os releases têm de
>   ser públicos** (repositório público). Num repositório privado a
>   atualização falha e fica registada no log.
> - Quem puder publicar releases neste repositório consegue executar código
>   como SYSTEM em todos os computadores da escola: proteja a conta do GitHub
>   com 2FA e limite quem tem acesso de escrita.
> - A versão 0.2.0 não traz o atualizador: instale a 0.3.0 uma vez à mão com o
>   `instalar.cmd`; a partir daí é automático.
> - Para desativar num computador:
>   `schtasks /Change /TN AEGN-Atualizar /Disable` (como administrador).

## Comandos

Tudo o que altera o computador é **simulação** até se passar `--aplicar`.

| Comando | O que faz |
|---|---|
| `aegn` / `aegn menu` | Menu interativo: saída ao vivo; em modo real pede a senha. |
| `aegn executar` | Processo completo: inventário, administradores, desinstalação, AppLocker e firewall. Opções `--simples`, `--sem-rustdesk`, `--sem-opencode`, `--sem-politicas`, `--so-auditoria`, `--sem-firewall`, `--aplicar`. |
| `aegn estado` | Estado do AppLocker/AppIDSvc, regras de firewall, tarefa agendada e senha. |
| `aegn reverter` | Desfaz tudo o que o agente aplicou (não reinstala software). |
| `aegn auditoria listar` | Inventário do software instalado (chaves Uninstall do registo). |
| `aegn auditoria admins` | Membros do grupo local de Administradores. |
| `aegn auditoria remover <nome>` | Desinstala software não autorizado (winget, ou a UninstallString). |
| `aegn politica impor [--so-auditoria]` | Política AppLocker (Exe, Script e MSI). |
| `aegn politica eventos [--max N]` | Últimos bloqueios e avisos de auditoria do AppLocker. |
| `aegn politica estado` / `reverter` | Estado / remoção das regras AppLocker AEGN. |
| `aegn firewall estado` / `impor` / `reverter` | Bloqueio de saída do RustDesk, AnyDesk e TeamViewer. |
| `aegn tarefa instalar [--so-auditoria]` / `estado` / `remover` | Tarefa SYSTEM que volta a aplicar o processo no arranque e todos os dias. |
| `aegn senha alterar` / `estado` / `verificar` | Senha de administração do AEGN. |
| `aegn atualizar [--aplicar]` / `atualizar estado` | Procura e instala versões novas do GitHub (sem administrador nem senha). |

Os nomes da versão 0.1 (`run`, `status`, `policy enforce`, `--apply`…)
continuam a funcionar.

## Implantação recomendada numa sala

1. Instalar com o `instalar.cmd` e mudar a senha.
2. `aegn executar --so-auditoria --aplicar`: o AppLocker só regista, não bloqueia.
3. Usar os computadores alguns dias e rever `aegn politica eventos`: cada
   linha `AUDIT` é algo que seria bloqueado (Teams, OneDrive ou VS Code
   instalados por utilizador, scripts de início de sessão…).
4. `aegn executar --aplicar`: ativa o bloqueio.
5. `aegn tarefa instalar --aplicar`: o computador corrige-se sozinho todos os
   dias. Registo em `C:\Program Files\AEGN\logs\aegn.log`.

## Proteções

- **AppLocker** (Exe, Script e MSI): só se executa o que está em `%WINDIR%`
  ou `%PROGRAMFILES%` (MSI: `%WINDIR%\Installer`); os administradores podem
  tudo. Ficam assim bloqueados `.exe`, `.ps1/.bat/.cmd/.vbs/.js` e `.msi`
  vindos de Transferências, Ambiente de Trabalho, AppData, Documentos ou uma
  pen USB. AppData\Local e Transferências têm ainda um Deny explícito que se
  aplica **também aos administradores**.
- **Firewall**: bloqueio de saída das portas do RustDesk (21114-21119),
  AnyDesk (6568) e TeamViewer (5938). O AnyDesk e o TeamViewer podem sair pela
  porta 443; para os cortar de vez é preciso filtrar por domínio (proxy ou DNS).
- **Administradores locais**: o inventário lista-os. Um aluno que seja
  administrador consegue contornar tudo o resto.
- **Tarefa agendada**: corre como SYSTEM, por isso só se instala se o
  `aegn.exe` estiver dentro de Program Files; se um utilizador pudesse
  substituir o executável, seria uma escalada de privilégios.

> [!WARNING]
> Num computador com o AppLocker já ativo, um `instalar.cmd` dentro de
> Transferências só corre com **Executar como administrador** (os scripts fora
> de Windows e Program Files estão bloqueados para quem não é administrador).

## Segurança e desenho

- **Simulação por defeito**: nada muda no computador sem `--aplicar` e a senha.
  Exceção: `aegn atualizar --aplicar` não pede a senha, porque só instala o
  release oficial, e fá-lo pela tarefa SYSTEM.
- **Reversível**: o AppLocker e o firewall só tocam nas regras próprias
  (`AEGN-Deny-UserFolders`, grupo `AEGN-RemoteAccess`); o resto da política
  local mantém-se. `aegn reverter --aplicar` desfaz tudo.
- **Privilégios**: as operações de sistema exigem consola de administrador.
- **Edições**: o AppLocker só atua no Windows Pro/Enterprise/Education.

## Compilar

Os releases compilam-se no GitHub Actions (`.github/workflows/release.yml`)
ao subir uma etiqueta `vX.Y.Z`, que tem de coincidir com a versão do
`Cargo.toml`. O workflow gera o `aegn.exe`, o MSI (WiX 5) e o zip.

Em Windows, à mão:

```powershell
cargo build --release
dotnet tool install --global wix --version 5.0.2
wix build installer\aegn.wxs -arch x64 -d Version=0.3.0 -d ExePath=target\release\aegn.exe -o AEGN-Security-0.3.0-x64.msi
```

Em Linux pode verificar-se que o código de Windows compila (sem ligar):

```bash
cargo test
scripts/check-windows.sh clippy
```
