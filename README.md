# ARES

Plataforma modular de ciberdefesa **defensiva**: painel web e agentes Windows/Linux.

Nome de trabalho: **ARES**. Expansão provisória: *Adaptive Response & Event Security*.

> Projeto de portfólio, sem operação real. Use apenas em equipamentos e redes próprios ou com autorização explícita.

## Status

| Item | Estado |
|---|---|
| Especificação | Escrita (Especificação Geral v1.1 + Complemento v1.2). |
| Código | **Nenhuma funcionalidade implementada.** |
| Fase atual | 01a — preparação (item 1 da seção 21.13 da v1.1). |

## Documentação

| Documento | Conteúdo |
|---|---|
| [docs/ARES_Especificacao_Geral_e_Arquitetura_Core_v1.1.md](docs/ARES_Especificacao_Geral_e_Arquitetura_Core_v1.1.md) | Especificação geral e arquitetura do Core. Conversão do [.docx original](docs/ARES_Especificacao_Geral_e_Arquitetura_Core_v1.1.docx). |
| [docs/ARES_Core_v1.2_Complemento.md](docs/ARES_Core_v1.2_Complemento.md) | Complemento v1.2. Prevalece sobre a v1.1 em caso de conflito. |
| [docs/ENVIRONMENT.md](docs/ENVIRONMENT.md) | Versões reais das ferramentas de desenvolvimento. |
| [docs/adr/](docs/adr/) | Decisões arquiteturais. |

## Backend (desenvolvimento)

Requer [uv](https://docs.astral.sh/uv/), Python 3.14 e Docker Desktop.

1. Copie [.env.example](.env.example) para `.env` na raiz e troque **todas** as senhas. O `.env` fica fora do Git.
2. Suba o banco (PostgreSQL 18.6 em `127.0.0.1:5433`, ver [ADR 0001](docs/adr/0001-postgresql-em-docker-para-desenvolvimento.md)):

   ```powershell
   docker compose up -d --wait
   ```

3. Aplique as migrações e rode a API:

   ```powershell
   cd backend
   uv sync
   uv run alembic upgrade head
   uv run uvicorn app.main:app --host 127.0.0.1 --port 8000
   ```

4. Crie o primeiro administrador (só por linha de comando, como `ares_owner`; não existe rota HTTP para isso). A senha é pedida sem eco:

   ```powershell
   uv run python -m app.cli create-admin --email voce@exemplo.local --display-name "Seu Nome"
   ```

Conferir a integridade da trilha de auditoria (código de saída 3 se a cadeia estiver quebrada):

```powershell
uv run python -m app.cli verify-audit
```

O comando imprime a cabeça da cadeia (`<id>:<entry_hash>`). Guarde esse valor **fora do servidor**. Nas próximas verificações, passe `--expect-head <id>:<entry_hash>`: sem essa âncora, a remoção das últimas entradas não é detectada (ver [ADR 0004](docs/adr/0004-auditoria-e-logs-estruturados.md)).

Os logs saem em JSON, uma linha por evento, na saída padrão. Para um log de acesso no mesmo formato, rode o uvicorn com `--no-access-log` (o próprio ARES registra cada requisição, com `request_id`).

Testes: `uv run pytest`. Os testes de banco só rodam com `ARES_TEST_ADMIN_DATABASE_URL` definido (usuário que pode criar bancos); cada teste cria e apaga um banco temporário.

Usuários do banco:

| Usuário | Uso | Permissões |
|---|---|---|
| `ares_admin` | Bootstrap do contêiner e testes de banco (`ARES_TEST_ADMIN_DATABASE_URL`) | Superusuário. Nem a API nem as migrações usam. |
| `ares_owner` | Migrações (`ARES_MIGRATION_DATABASE_URL`) | Dono do banco e do schema; não é superusuário. |
| `ares_app` | API (`ARES_DATABASE_URL`) | Só o que cada migração concede, tabela por tabela; sem DDL; só conecta no banco `ares`. |

## Stack proposta

Python/FastAPI, React + TypeScript, PostgreSQL. Detalhes e status de cada decisão na especificação.

## Licença

[Apache-2.0](LICENSE).
