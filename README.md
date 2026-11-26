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

Requer [uv](https://docs.astral.sh/uv/) e Python 3.14.

```powershell
cd backend
uv sync
uv run pytest
uv run uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Configuração por variáveis `ARES_*` ou `backend/.env` (modelo em [backend/.env.example](backend/.env.example)).

## Stack proposta

Python/FastAPI, React + TypeScript, PostgreSQL. Detalhes e status de cada decisão na especificação.

## Licença

[Apache-2.0](LICENSE).
