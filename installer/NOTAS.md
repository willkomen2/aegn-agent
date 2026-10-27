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

- Interface toda em português (os comandos antigos em inglês continuam a funcionar).
- Senha de administração para tudo o que altera o computador (`--aplicar`).
  Por defeito: `admin`.
- Instalador MSI que adiciona o `aegn` ao PATH do sistema, e scripts
  `instalar.cmd` / `desinstalar.cmd`.
- Retirado o comando `gh` (não tinha utilidade para a escola).

### Ficheiros

| Ficheiro | Para quê |
|---|---|
| `AEGN-Security-…-windows.zip` | MSI + scripts de instalação. **Use este.** |
| `AEGN-Security-…-x64.msi` | Só o instalador (implantação por GPO/Intune). |
| `aegn.exe` | Executável solto, sem instalar. |
| `instalar.ps1` | Script de instalação (o mesmo do zip). |
| `SHA256SUMS.txt` | Somas de verificação. |
