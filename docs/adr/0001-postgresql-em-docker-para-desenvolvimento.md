# ADR 0001 — PostgreSQL em Docker para desenvolvimento

| Campo | Valor |
|---|---|
| Status | Aceito |
| Data | 2026-11-26 |
| Revisar até | 2026-12-10 |

## Contexto

- A v1.1 (seções 9, 19.2 e 21.5) define PostgreSQL como banco principal e Docker como ferramenta de ambiente de desenvolvimento, sem obrigar Docker em cada componente.
- A seção 21.1 pede decidir se o Docker será usado desde o início e onde ficará o banco de desenvolvimento.
- O item 3 da seção 21.13 (fase 01a) exige conexão PostgreSQL e primeira migração testada. A seção 16.1 exige migrações testadas em banco temporário.
- O ambiente real (`docs/ENVIRONMENT.md`) tem dois caminhos possíveis:
  - PostgreSQL 18.6 nativo, como serviço Windows (`postgresql-x64-18`), escutando na porta 5432 em todas as interfaces;
  - Docker 29.9.2 com WSL 2.

## Decisão

No desenvolvimento local, o PostgreSQL roda em contêiner Docker, definido em arquivo versionado no repositório. O serviço nativo não é usado pelo ARES.

## Confirmado

- Escolha do autor em 26/11/2026: PostgreSQL em contêiner Docker para desenvolvimento.
- PostgreSQL é o banco principal (v1.1, seção 19.2; CLAUDE.md, seção 4.2).
- Segredos fora do Git; só `.env.example` com valores fictícios (CLAUDE.md, seção 9.1).

## Proposto

- Usar volume nomeado para os dados de desenvolvimento.
- Passar as credenciais do banco por `.env`, que fica fora do Git. Os nomes das variáveis ficam documentados em `.env.example`.
- Criar um usuário de aplicação com privilégio mínimo, separado do superusuário (v1.1, seção 21.5).
- Nos testes de migração, usar banco ou contêiner temporário, descartado ao fim (v1.1, seção 16.1).

## Fechado com o autor em 26/11/2026

| Item | Decisão | Motivo |
|---|---|---|
| Versão da imagem | `postgres:18.6` (Debian), versão exata, sem `latest` | Mesma versão do PostgreSQL nativo. A 18.7 foi publicada em 26/11/2026 e é recente demais para fixar. |
| Porta no host | `127.0.0.1:5433` | Evita conflito com o serviço nativo na 5432 e não expõe o banco à rede local. |
| Arquivo de orquestração | `docker-compose.yml` na raiz | Estrutura indicativa da v1.1, seção 12. |
| Serviço nativo `postgresql-x64-18` | Parar e desativar | Hoje escuta em `0.0.0.0` e `::`. A execução depende de confirmação do autor no momento da alteração. |

## Em aberto

| Item | Alternativas | Risco de adiar |
|---|---|---|
| Limites de CPU e RAM do WSL/Docker | Definir em `.wslconfig` ou manter o padrão | Consumo excessivo numa máquina de 16 GB (v1.1, seção 21.1). |
| Backup dos dados de desenvolvimento | Sem backup (dados descartáveis) ou `pg_dump` periódico | Baixo enquanto os dados forem sintéticos. |
| Atualização de patch da imagem | Revisar a cada release menor ou na data de revisão | Correções de segurança acumuladas na imagem fixada. |

## Consequências

- O ambiente de banco fica reproduzível a partir do repositório. Ele é recriado do zero com um comando.
- O desenvolvimento passa a depender do Docker Desktop estar em execução.
- Os testes de integração e de migração rodam sobre um banco isolado, sem tocar no PostgreSQL nativo.
- O PostgreSQL nativo deve ser parado e desativado. Até essa alteração ser feita, ele continua exposto à rede local.
- Isto não define o banco de produção nem de demonstração. Esse ambiente precisa de decisão própria.
