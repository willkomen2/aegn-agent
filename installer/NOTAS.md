## AEGN Security — sistema de segurança dos computadores da Escola AEGN

### Instalar

1. Descarregue **AEGN-Security-…-windows.zip** e extraia-o.
2. Clique com o botão direito em **instalar.cmd** → **Executar como administrador**.
3. Defina a senha de administração do AEGN (Enter = `admin`).

O `aegn.exe` fica em `C:\Program Files\AEGN` e o comando `aegn` fica no PATH:
abra uma consola de administrador nova e escreva `aegn`.

Também pode instalar só o MSI (`msiexec /i AEGN-Security-…-x64.msi`). Nesse
caso a senha fica `admin` até a alterar com `aegn senha alterar`.

### Novidades

- **Correção urgente: menu Iniciar bloqueado e botões de energia** (0.8.1):
  - O AppLocker deixa de bloquear o menu Iniciar, a pesquisa e as Definições
    ("o administrador bloqueou esta aplicação"): com regras Exe ativas e sem
    regras de apps empacotadas, o Windows bloqueava todas as apps empacotadas,
    também aos administradores. A política do AEGN passa a permiti-las.
  - O resgate da 0.8.0 parava o AppIDSvc antes de a política vazia chegar ao
    driver, e o bloqueio continuava. Agora mantém o serviço a correr, apaga a
    cache `C:\Windows\System32\AppLocker\*.AppLocker`, só depois o para, e
    reabre o menu Iniciar. Registo em `C:\ProgramData\AEGN\desbloquear.log`.
  - Novo `aegn energia --aplicar`: repõe os botões Encerrar e Reiniciar
    (NoClose, HidePowerOptions, diretivas MDM de Start, entradas do gpedit em
    Registry.pol, com cópia, e o direito "Encerrar o sistema"). Corre ao
    instalar e em cada execução da atualização automática.
  - Os PCs com a 0.8.0 atualizam-se sozinhos; se o menu Iniciar ainda não
    abrir, reinicie.

- **Resgate: computador desbloqueado ao instalar** (0.8.0): o instalador e a
  atualização executam `aegn desbloquear --aplicar`, que esvazia o AppLocker
  local (guarda cópia em C:\ProgramData\AEGN), põe o AppIDSvc em manual,
  retira as regras de firewall e as diretivas de navegador do AEGN, remove a
  tarefa AEGN-Agent e desmonta perfis HKU\AEGN_*. Reinicie depois. A
  atualização automática espera 2 min após o arranque e 15 min após o início
  de sessão. Minecraft Education deixa de ser desinstalado; a limpeza usa um
  só PowerShell e não recorre ao winget.

- **Correção urgente: sessão congelada ao iniciar** (0.7.1): a limpeza deixa
  de montar o NTUSER.DAT dos perfis sem sessão (se não o desmontava, o Windows
  não conseguia abrir o perfil e o ambiente de trabalho ficava congelado, em
  alunos e administradores). O instalador e a atualização desmontam os que
  versões anteriores deixaram em HKEY_USERS\AEGN_*.

- **AppLocker passa a lista negra** (0.7.0): já nada fica bloqueado ao
  iniciar sessão. Tudo se executa, exceto, nas contas de aluno, o RustDesk,
  AnyDesk, TeamViewer, Roblox, Steam e Battle.net (negados pela assinatura,
  mesmo portáteis ou renomeados). Os administradores nunca são bloqueados.
  O instalador substitui sozinho as regras das versões anteriores.

- **Instalar programas com a senha do AEGN** (0.6.0): `aegn instalar
  <ficheiro.exe|.msi>` pede a senha do AEGN (por defeito `admin`) e abre o
  instalador elevado; o Windows pede então uma conta de administrador. Serve
  para instalar a partir de Transferências ou de uma pen USB numa conta de
  aluno. Os administradores também deixam de ser bloqueados sem elevar: cada
  conta do grupo Administradores tem a sua própria regra.

- **AppLocker já não bloqueia o Windows nem os administradores** (0.5.2): saem
  as regras Deny de AppData\Local e Transferências, que se aplicavam também aos
  administradores e impediam o arranque do ambiente de trabalho ao iniciar
  sessão. Passa a permitir-se o que vem assinado pela Microsoft, Google
  (Chrome) e Mozilla (Firefox), mesmo instalado só para o utilizador. O
  instalador (e com ele a atualização automática) corrige sozinho os PCs que
  já tinham as regras antigas.

- **Atualização logo ao ligar o PC** (0.5.1): a tarefa `AEGN-Atualizar` corre
  30 segundos depois do arranque (antes eram 5 minutos) e também ao iniciar
  sessão; se a rede ainda não estiver pronta, tenta de novo durante 5 minutos.

- **Contas Google fechadas ao terminar a sessão** (0.5.0): Chrome, Edge e
  Firefox apagam as cookies ao fechar, e com elas as contas Google (ou outras)
  que ficaram abertas; o Chrome deixa de permitir iniciar sessão no navegador
  e de sincronizar. O instalador e a atualização automática aplicam-no.
  Ver/retirar: `aegn navegador estado`, `aegn navegador reverter --aplicar`;
  no processo, `--sem-navegador`.

- **Desinstalação por defeito** de jogos e lançadores (Steam, Riot Client e
  Vanguard, VALORANT, League of Legends, Epic Games, Battle.net, EA app,
  Ubisoft Connect, GOG Galaxy, Roblox), Spotify, Lively Wallpaper, Custom
  Cursor e CursorFX (além de RustDesk e OpenCode), em todos os perfis de
  utilizador e na Microsoft Store, mais P2P, utilitários de limpeza duvidosos,
  acesso remoto e emuladores de Android. Apaga os restos e repõe o cursor do
  Windows. Tailscale, Git e o software do sistema ficam sempre. Desativar:
  `--sem-limpeza`.
- **Auditoria**: `aegn auditoria listar` mostra data de instalação, quem
  instalou e editor; `detalhe <nome>`, `suspeitos`, `limpar` e `rasto`
  (instaladores descarregados e eventos com a conta que instalou).
- **Histórico de desinstalações**: `aegn auditoria historico` mostra quando, em
  que perfil e como foi desinstalado cada programa.
- **Atualização automática** (desde a 0.4.0): a tarefa `AEGN-Atualizar`
  (SYSTEM) instala as versões novas do GitHub sem UAC nem senha.
- A senha de administração já não se perde ao atualizar com o MSI.

### Ficheiros

| Ficheiro | Para quê |
|---|---|
| `AEGN-Security-…-windows.zip` | MSI + scripts de instalação. **Use este.** |
| `AEGN-Security-…-x64.msi` | Só o instalador (implantação por GPO/Intune). |
| `aegn.exe` | Executável solto, sem instalar. |
| `instalar.ps1` | Script de instalação (o mesmo do zip). |
| `SHA256SUMS.txt` | Somas de verificação. |
