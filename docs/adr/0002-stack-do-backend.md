# ADR 0002 — Stack do backend

| Campo | Valor |
|---|---|
| Status | Aceito |
| Data | 2026-11-26 |
| Revisar até | 2026-12-10 |

## Contexto

- A v1.1 (seções 9 e 19.2) propõe Python/FastAPI para Core e API, e PostgreSQL como banco principal.
- A seção 21.2 pede confirmar Python como linguagem do Core, FastAPI para a API, a versão suportada, o gerenciador de dependências e o servidor ASGI.
- A seção 21.5 pede fixar a versão do PostgreSQL e a ferramenta de migrações.
- O CLAUDE.md (seção 4.2) registra Python/FastAPI, React + TypeScript e PostgreSQL como decisões a confirmar com o autor.
- O ambiente real (`docs/ENVIRONMENT.md`, seção 2) tem Python 3.14.7 instalado.
- A verificação de compatibilidade está em `docs/ENVIRONMENT.md`, seção 4. Ela mostra que a maioria das bibliotecas candidatas declara suporte ao Python 3.14. Não é prova de funcionamento: a prova é a suíte de testes.
- O `slowapi` não declara suporte ao Python 3.14. Não entra nesta decisão.

## Decisão

- Linguagem: Python 3.14.
- Gerenciador de dependências e ambiente: uv, com lockfile versionado.
- API: FastAPI.
- Servidor ASGI: uvicorn.
- Persistência: SQLAlchemy 2.x, com acesso síncrono.
- Driver PostgreSQL: psycopg 3, em modo síncrono.
- Migrações: Alembic.
- Validação e configuração: Pydantic 2 e pydantic-settings.

## Confirmado

- Python como linguagem principal do Core e FastAPI como API (v1.1, seções 9 e 19.2; CLAUDE.md, seção 4.2).
- PostgreSQL como banco principal (v1.1, seção 19.2).
- Escolha do autor em 26/11/2026: banco síncrono, uv como gerenciador e psycopg 3 como driver, com registro da análise de licença LGPL-3.0 do psycopg antes da publicação (ver `docs/ENVIRONMENT.md`, seção 4).
- Licença do projeto: Apache-2.0 (complemento, seção 1, item 5).

## Proposto

- Lockfile do uv versionado no repositório. Versões exatas fixadas no lockfile, conferidas contra as tabelas de `docs/ENVIRONMENT.md`.
- Pydantic para validação de entrada, com lista explícita de campos aceitos por rota (complemento, seção 3.3).
- Alembic para migrações, com testes em banco temporário (v1.1, seção 16.1).
- Argon2id via `argon2-cffi` para senhas (CLAUDE.md, seção 9.1).

## Em aberto

| Item | Alternativas | Risco de adiar |
|---|---|---|
| Biblioteca de rate limit | `slowapi` (não declara Python 3.14), implementação própria sobre o PostgreSQL, ou outra biblioteca | Teste de inundação por agente e limite de login são prioridade alta (complemento, seções 4.1 e 3.2). Bloqueia a fase 01a. |
| Manutenção do `argon2-cffi` | Manter a versão atual ou trocar | Último release em jun/2025. Confirmar antes de fixar. |
| Instalação do `uv` no PATH | Remover o `uv` 0.12.13 do Hermes ou apontar o PATH para o winget (0.13.10) | Versões diferentes entre sessões e ferramentas. Ver `docs/ENVIRONMENT.md`, seção 2. |
| Tipagem estática | `mypy` ou outra ferramenta | Baixo. Não afeta a stack principal. |
| Frontend (React + TypeScript) | Decisão própria, fora deste ADR | Bloqueia só a fase 08 (dashboard). |

## Consequências

- Uma única linguagem no backend, com ecossistema maduro para FastAPI e SQLAlchemy.
- Acesso síncrono é mais simples de escrever, testar e depurar. O FastAPI executa rotas `def` em threadpool. A meta de 100 eventos/s (v1.1, seção 11) precisa ser medida; se não for atingida, a decisão é revisada.
- Trocar para acesso assíncrono depois é trabalho grande: exige reescrever a camada de persistência e os testes. Por isso esta decisão é difícil de reverter.
- O uso de psycopg (LGPL-3.0) exige o registro da análise de licença antes da publicação.
- Esta decisão não define versões finais de cada biblioteca. Isso fica no lockfile.
