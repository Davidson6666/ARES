# Ambiente de desenvolvimento — ARES

| Campo | Valor |
|---|---|
| Documento | Registro do ambiente real de desenvolvimento |
| Versão | 1.0 |
| Data da verificação | 26/11/2026 |
| Método | Verificação somente leitura (PowerShell). Nada foi instalado ou alterado. |

## 1. Sistema

| Item | Valor encontrado |
|---|---|
| Sistema operacional | Windows 11 Pro (edição `Professional`), versão 10.0.26300, build 26300 |
| Máquina | Acer Nitro ANV15-51 |
| CPU | Intel Core i7-13620H, 10 núcleos, 16 threads |
| RAM | 15,7 GB |
| Disco C: | 99,7 GB livres de 475,1 GB |
| Virtualização | Hipervisor presente (`HypervisorPresent = True`). O campo `VirtualizationFirmwareEnabled` retorna `False`, o que é esperado quando o Hyper-V já está ativo. |

## 2. Ferramentas

| Ferramenta | Versão | Caminho | Observação |
|---|---|---|---|
| WSL | Versão padrão 2 | `C:\WINDOWS\system32\wsl.exe` | Única distribuição: `docker-desktop` (parada no momento da verificação). Sem distribuição Linux de uso geral. |
| Docker Desktop | Docker 29.9.2 (build a82e528) | `C:\Users\david\AppData\Local\Programs\DockerDesktop\resources\bin\docker.exe` | — |
| Python | 3.14.7 | `C:\Python314\python.exe` | `py` launcher também aponta para 3.14.7. |
| Node.js | v24.20.0 | `C:\Program Files\nodejs\node.exe` | — |
| npm | 11.19.0 | `C:\Program Files\nodejs\npm.ps1` | — |
| Git | 2.55.0.windows.2 | `C:\Program Files\Git\cmd\git.exe` | — |
| PostgreSQL | 18.6 | `C:\Program Files\PostgreSQL\18\bin\` | Serviço `postgresql-x64-18` em execução. `psql` **não está no PATH**. |

## 3. Pontos em aberto

- **PostgreSQL local × contêiner:** o autor escolheu em 26/11/2026 o **PostgreSQL em contêiner Docker** para desenvolvimento. Ainda falta definir a versão da imagem e o ADR. O serviço nativo `postgresql-x64-18` escuta na porta 5432, em todas as interfaces (`0.0.0.0` e `::`). O contêiner deve usar outra porta ou o serviço nativo deve ser parado, com confirmação do autor.
- **`psql` fora do PATH:** usar caminho completo ou adicionar ao PATH (alteração de sistema, exige confirmação do autor).
- **Python 3.14:** confirmar compatibilidade das dependências escolhidas (FastAPI, driver PostgreSQL, Argon2) antes de fixar versões.

## 4. Histórico de versões

| Versão | Data | Alteração |
|---|---|---|
| 1.0 | 26/11/2026 | Primeira verificação do ambiente. |
| 1.1 | 26/11/2026 | Registrada a escolha de PostgreSQL em Docker para desenvolvimento. |
