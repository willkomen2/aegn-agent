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

A partir da versão 0.4.0, cada computador atualiza-se sozinho a partir dos
[releases](../../releases) deste repositório, **sem UAC nem senha**:

- o MSI instala o `atualizar.ps1` em `C:\Program Files\AEGN` e regista a
  tarefa `AEGN-Atualizar`, que corre como **SYSTEM** 30 segundos depois do
  arranque (esperando pela rede se for preciso), quando alguém inicia sessão e
  todos os dias entre as 13:00 e as 14:00 (o atraso aleatório evita
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
> - A versão 0.2.0 não traz o atualizador: instale a 0.4.0 uma vez à mão com o
>   `instalar.cmd`; a partir daí é automático.
> - Para desativar num computador:
>   `schtasks /Change /TN AEGN-Atualizar /Disable` (como administrador).

## Comandos

Tudo o que altera o computador é **simulação** até se passar `--aplicar`.

| Comando | O que faz |
|---|---|
| `aegn` / `aegn menu` | Menu interativo: saída ao vivo; em modo real pede a senha. |
| `aegn executar` | Processo completo: inventário, administradores, desinstalação, limpeza da lista negra, AppLocker e firewall. Opções `--simples`, `--sem-rustdesk`, `--sem-opencode`, `--sem-limpeza`, `--sem-politicas`, `--so-auditoria`, `--sem-firewall`, `--sem-navegador`, `--aplicar`. |
| `aegn navegador estado\|impor\|reverter [--aplicar]` | Chrome, Edge e Firefox apagam as cookies ao fechar: ao terminar a sessão do Windows não fica nenhuma conta Google aberta. O MSI aplica-o ao instalar e ao atualizar. |
| `aegn estado` | Estado do AppLocker/AppIDSvc, regras de firewall, tarefa agendada e senha. |
| `aegn reverter` | Desfaz tudo o que o agente aplicou (não reinstala software). |
| `aegn auditoria listar` | Inventário: data de instalação, quem instalou, editor e tamanho (registo + Microsoft Store). |
| `aegn auditoria detalhe <nome>` | Tudo o que se sabe de um programa: versão, pasta, origem e comando de desinstalação. |
| `aegn auditoria suspeitos` | Só o software da lista negra (Roblox, Spotify, Lively Wallpaper, cursores, jogos, acesso remoto). |
| `aegn auditoria limpar [--aplicar]` | Desinstala a lista negra, apaga os restos e repõe o cursor do Windows. |
| `aegn auditoria rasto` | Instaladores descarregados, eventos do Windows com a conta que instalou e arranque automático. |
| `aegn auditoria admins` | Membros do grupo local de Administradores. |
| `aegn auditoria remover <nome>` | Desinstala software não autorizado em todos os perfis e na Microsoft Store. |
| `aegn politica impor [--so-auditoria]` | Política AppLocker (Exe, Script e MSI). |
| `aegn politica eventos [--max N]` | Últimos bloqueios e avisos de auditoria do AppLocker. |
| `aegn politica estado` / `reverter` | Estado / remoção das regras AppLocker AEGN. |
| `aegn firewall estado` / `impor` / `reverter` | Bloqueio de saída do RustDesk, AnyDesk e TeamViewer. |
| `aegn tarefa instalar [--so-auditoria]` / `estado` / `remover` | Tarefa SYSTEM que volta a aplicar o processo no arranque e todos os dias. |
| `aegn senha alterar` / `estado` / `verificar` | Senha de administração do AEGN. |
| `aegn atualizar [--aplicar]` / `atualizar estado` | Procura e instala versões novas do GitHub (sem administrador nem senha). |

Os nomes da versão 0.1 (`run`, `status`, `policy enforce`, `--apply`…)
continuam a funcionar.

## Auditoria: quem instalou o quê e quando

`aegn auditoria listar` mostra, por programa: **origem** (`HKLM64`, `HKLM32`,
`HKCU` ou `APPX`), **data de instalação**, **quem instalou** e o editor. A
atribuição vem de dados que o próprio Windows guarda:

- **Data**: `InstallDate` do instalador; se faltar, a última escrita da chave do
  registo; por fim, a data de criação da pasta de instalação.
- **Quem**: as chaves `HKCU` só as escreve o utilizador da sessão (a instalação
  não pediu administrador); `HKLM` exige administrador e aparece como
  `todos (admin)`.
- **Rasto** (`aegn auditoria rasto`): instaladores descarregados para
  Transferências, eventos `MsiInstaller` do Windows — que incluem a **conta que
  lançou a instalação** — e programas de arranque automático.

Isto é auditoria local e transparente: nada sai do computador e não há
vigilância de conteúdo, só os metadados de instalação que o Windows já tem.

## Limpeza da lista negra

`aegn auditoria limpar --aplicar` desinstala o software que a escola não admite
e apaga os restos, numa só passagem:

| Regra | O que apanha |
|---|---|
| `roblox` | Roblox Player e Roblox Studio (instalação por utilizador). |
| `spotify` | Spotify (Store ou instalador clássico). |
| `lively` | Lively Wallpaper e fundos animados. |
| `cursor` | Aplicações de cursores personalizados; os `.ani`/`.cur` descarregados e o esquema de ponteiros voltam ao predefinido. |
| `jogos` | Steam, Epic, Riot, Valorant, Minecraft/TLauncher, Fortnite, EA, GOG, Battle.net. |
| `p2p` | uTorrent, BitTorrent, qBittorrent. |
| `limpeza` | CCleaner, Driver Booster, Advanced SystemCare, Glary. |
| `remoto` | RustDesk, AnyDesk, TeamViewer. |
| `emulador` | BlueStacks, LDPlayer, NoxPlayer, MEmu. |

A remoção usa `Remove-AppxPackage` nas apps da Store, `winget` e, por fim, a
`UninstallString` do registo. Uma **lista branca** protege o sistema: Windows,
drivers (HP, NVIDIA, Intel, Realtek), Microsoft 365/Teams/Edge, Chrome,
**Tailscale** e **Git** nunca são tocados, mesmo que uma regra coincida.

Como tudo o resto, sem `--aplicar` é simulação: mostra o plano e não altera
nada.

## Implantação recomendada numa sala

1. Instalar com o `instalar.cmd` e mudar a senha.
2. `aegn executar --so-auditoria --aplicar`: o AppLocker só regista, não bloqueia.
3. Usar os computadores alguns dias e rever `aegn politica eventos`: cada
   linha `AUDIT` é algo que seria bloqueado (Teams, OneDrive ou VS Code
   instalados por utilizador, scripts de início de sessão…).
4. `aegn executar --aplicar`: ativa o bloqueio.
5. `aegn tarefa instalar --aplicar`: o computador corrige-se sozinho todos os
   dias. Registo em `C:\Program Files\AEGN\logs\aegn.log`.

## Software não autorizado

O `aegn executar` desinstala por defeito o **RustDesk**, o **OpenCode**,
os jogos e os seus lançadores (**Steam**, **Riot Client**, **Riot Vanguard**,
**VALORANT**, **League of Legends**, **Epic Games**, **Battle.net**, **EA app**,
**Ubisoft Connect**, **GOG Galaxy**, **Roblox**), o **Spotify**, o
**Lively Wallpaper**, o **Custom Cursor** e o **CursorFX** (a lista está em
`src/audit.rs`, `APPS`; o Minecraft fica de fora por causa do Minecraft
Education). Para cada um:

- instalação do computador: o desinstalador do próprio programa, em silêncio;
- instalação por utilizador (Roblox, Spotify...): em **todos os perfis**,
  mesmo sem sessão aberta, fecha o programa e apaga a sua pasta de AppData e a
  entrada do registo (o desinstalador correria no perfil do administrador);
- versão da Microsoft Store: `Remove-AppxPackage` para todos os utilizadores.

Cada desinstalação fica em `C:\Program Files\AEGN\logs\desinstalacoes.csv`
(data, computador, perfil, programa, versão, método e resultado), que o
`aegn auditoria historico` e o `aegn auditoria listar` mostram.

```powershell
aegn auditoria listar                 # o que há e o que não é autorizado
aegn executar --simples --aplicar     # desinstalar já (e aplicar as proteções)
aegn auditoria historico              # o que foi desinstalado e quando
```

## Proteções

- **AppLocker** (Exe, Script e MSI): só se executa o que está em `%WINDIR%`
  ou `%PROGRAMFILES%` (MSI: `%WINDIR%\Installer`); os administradores podem
  tudo. Ficam assim bloqueados `.exe`, `.ps1/.bat/.cmd/.vbs/.js` e `.msi`
  vindos de Transferências, Ambiente de Trabalho, AppData, Documentos ou uma
  pen USB. Os administradores **nunca** são bloqueados. Também se permite,
  esteja onde estiver, o que vem assinado pela Microsoft (OneDrive, Teams,
  componentes do Windows que arrancam ao iniciar sessão), pela Google (Chrome)
  e pela Mozilla (Firefox), mesmo instalados só para o utilizador.
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
wix build installer\aegn.wxs -arch x64 -d Version=0.5.2 -d ExePath=target\release\aegn.exe -o AEGN-Security-0.5.2-x64.msi
```

Em Linux pode verificar-se que o código de Windows compila (sem ligar):

```bash
cargo test
scripts/check-windows.sh clippy
```
