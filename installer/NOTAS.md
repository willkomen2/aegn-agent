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

- **Desinstalação por defeito** de Lively Wallpaper, Custom Cursor, CursorFX,
  Roblox e Spotify (além de RustDesk e OpenCode), em todos os perfis de
  utilizador e na Microsoft Store. Desativar: `--sem-aplicacoes`.
- **Histórico de desinstalações**: `aegn auditoria historico` mostra quando, em
  que perfil e como foi desinstalado cada programa; o `auditoria listar` mostra
  também o software não autorizado encontrado.
- **Atualização automática** (desde a 0.3.0): a tarefa `AEGN-Atualizar`
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
