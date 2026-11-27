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
| uv (instalado via winget, `astral-sh.uv`) | 0.13.10 | `C:\Users\david\AppData\Local\Microsoft\WinGet\Packages\astral-sh.uv_Microsoft.Winget.Source_8wekyb3d8bbwe\uv.exe` | Instalado em 26/11/2026. **Conflito de PATH:** `uv` resolve primeiro para `C:\Users\david\AppData\Local\hermes\bin\uv.exe` (0.12.13), instalado por outra ferramenta. Não alterado. |
| PostgreSQL | 18.6 | `C:\Program Files\PostgreSQL\18\bin\` | Serviço `postgresql-x64-18` em execução. `psql` **não está no PATH**. |

## 3. Pontos em aberto

- **PostgreSQL local × contêiner:** o autor escolheu em 26/11/2026 o **PostgreSQL em contêiner Docker** para desenvolvimento. Ainda falta definir a versão da imagem e o ADR. O serviço nativo `postgresql-x64-18` escuta na porta 5432, em todas as interfaces (`0.0.0.0` e `::`). O contêiner deve usar outra porta ou o serviço nativo deve ser parado, com confirmação do autor.
- **`psql` fora do PATH:** usar caminho completo ou adicionar ao PATH (alteração de sistema, exige confirmação do autor).
- **Python 3.14:** confirmar compatibilidade das dependências escolhidas (FastAPI, driver PostgreSQL, Argon2) antes de fixar versões.

## 3.1 Imagens Docker

| Imagem | Digest | Verificado em |
|---|---|---|
| `postgres:18.6` | `sha256:e3d24f6906d0760bf4da0dae872415391ededefad23fd471c47dc53b0ddf3c42` | 26/11/2026 (`docker image inspect`) |

## 3.2 Calibração do Argon2id (argon2-cffi 25.1.0)

Medido em 26/11/2026, com a média de 5 verificações.

| Parâmetros | Tempo |
|---|---|
| t=3, m=64 MiB, p=4 (padrão RFC 9106) | 48 ms |
| t=6, m=64 MiB, p=4 | 78 ms |
| **t=10, m=64 MiB, p=4 (escolhido, ADR 0003)** | **125 ms** |
| t=4, m=128 MiB, p=4 | 120 ms |
| t=3, m=256 MiB, p=4 | 194 ms |

## 4. Dependências candidatas do backend (não instaladas)

Verificadas no PyPI em 26/11/2026 (versão mais recente, data de upload e declaração de suporte ao Python 3.14 nos classificadores). Isto **não** prova compatibilidade em uso real; a prova é a suíte de testes passando. As versões exatas serão fixadas no lockfile.

| Pacote | Versão | Upload | Python 3.14 | Licença |
|---|---|---|---|---|
| fastapi | 0.165.0 | 2026-11-18 | Declarado | MIT |
| uvicorn | 0.54.0 | 2026-09-25 | Declarado | BSD-3-Clause |
| pydantic | 2.14.4 | 2026-11-19 | Declarado | MIT |
| pydantic-settings | 2.16.3 | 2026-11-13 | Declarado | MIT |
| sqlalchemy | 2.1.9 | 2026-11-16 | Declarado | MIT |
| alembic | 1.20.1 | 2026-10-22 | Declarado | MIT |
| psycopg | 3.3.9 | 2026-11-12 | Declarado | **LGPL-3.0-only** |
| argon2-cffi | 25.1.0 | 2025-06-03 | Declarado | MIT |
| pyotp | 2.12.1 | 2026-11-19 | Declarado | MIT |
| structlog | 26.1.0 | 2026-06-06 | Declarado | MIT ou Apache-2.0 |
| cryptography | 50.0.2 | (verificar no PyPI) | Não verificado | Apache-2.0 ou BSD-3-Clause |
| pytest | 9.2.0 | 2026-10-27 | Declarado | MIT |
| httpx | 0.29.0 | 2026-11-26 | Declarado | BSD-3-Clause |
| ruff | 0.17.6 | 2026-11-19 | Declarado | MIT |
| mypy | 2.4.1 | 2026-10-28 | Declarado | MIT |
| uv | 0.13.10 | 2026-11-24 | Declarado | MIT ou Apache-2.0 |
| slowapi | 0.1.10 | 2026-06-13 | **Não declarado** | MIT |

Pontos de atenção:

- `psycopg` é LGPL-3.0. Decisão do autor em 26/11/2026: usar como biblioteca importada e registrar a análise antes da publicação (CLAUDE.md, seção 4.3).
- `argon2-cffi` tem o último release em jun/2025. Confirmar se está mantido antes de fixar.
- `slowapi` não declara Python 3.14. O rate limit (complemento, seção 4.1) precisa de outra solução. Em aberto.
- `uv` não está instalado. A instalação altera o sistema e depende de confirmação do autor.

## 5. Histórico de versões

| Versão | Data | Alteração |
|---|---|---|
| 1.0 | 26/11/2026 | Primeira verificação do ambiente. |
| 1.1 | 26/11/2026 | Registrada a escolha de PostgreSQL em Docker para desenvolvimento. |
| 1.2 | 26/11/2026 | Tabela de dependências candidatas do backend verificadas no PyPI. |
| 1.3 | 26/11/2026 | Digest da imagem `postgres:18.6`. |
