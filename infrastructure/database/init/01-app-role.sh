#!/usr/bin/env bash
# Executado pela imagem postgres só na primeira inicialização do volume,
# como o superusuário POSTGRES_USER (usado apenas para este bootstrap).
#
# Papéis (ADR 0001; v1.1, seção 21.5):
# - ares_owner: dono do banco e do schema public. Roda as migrações.
#   Sem SUPERUSER, CREATEDB nem CREATEROLE.
# - ares_app:   usado pela API. Só CONNECT e USAGE no schema. Sem DDL e
#   sem privilégio padrão em tabelas: cada migração concede, tabela por
#   tabela, só o que a API precisa (ex.: audit_logs sem UPDATE/DELETE).
set -euo pipefail

: "${OWNER_DB_PASSWORD:?OWNER_DB_PASSWORD não definido}"
: "${APP_DB_PASSWORD:?APP_DB_PASSWORD não definido}"

# Senhas lidas do ambiente com \getenv: não aparecem na linha de comando
# do processo. Nomes passam como variáveis do psql (:'x' e :"x"), sem
# expansão de shell no heredoc, para evitar injeção.
psql -v ON_ERROR_STOP=1 \
  -v dbname="$POSTGRES_DB" \
  --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'SQL'
\getenv owner_password OWNER_DB_PASSWORD
\getenv app_password APP_DB_PASSWORD
-- Se algum comando falhar, o servidor não grava o texto (com a senha) no log.
SET log_min_error_statement = panic;

CREATE ROLE ares_owner LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD :'owner_password';
CREATE ROLE ares_app   LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD :'app_password';

RESET log_min_error_statement;

ALTER DATABASE :"dbname" OWNER TO ares_owner;
ALTER SCHEMA public OWNER TO ares_owner;

REVOKE ALL ON DATABASE :"dbname" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"dbname" TO ares_app;
REVOKE CONNECT ON DATABASE postgres FROM PUBLIC;
REVOKE CONNECT ON DATABASE template1 FROM PUBLIC;

REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO ares_app;
SQL
