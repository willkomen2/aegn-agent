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
