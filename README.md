# ARES

Plataforma modular de ciberdefesa **defensiva**: painel web e agentes Windows/Linux.

Nome de trabalho: **ARES**. Expansão provisória: *Adaptive Response & Event Security*.

> Projeto de portfólio, sem operação real. Use apenas em equipamentos e redes próprios ou com autorização explícita.

## Status

| Item | Estado |
|---|---|
| Especificação | Escrita (Especificação Geral v1.1 + Complemento v1.2). |
| Código | Core (fases 01a e 01b, com testes) em `backend/`; agente Windows (fase 04a) em desenvolvimento em `agent/`. Sem frontend. |
| Fase atual | 04a — primeiro agente, como processo do usuário ([ADR 0007](docs/adr/0007-agente-windows-04a.md)). |

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

MFA e recuperação de conta (ADR 0005):

```powershell
uv run python -m app.cli generate-mfa-key        # coloque o resultado em ARES_MFA_KEY, no .env
uv run python -m app.cli issue-recovery --email voce@exemplo.local   # token de 15 min, uso único
```

`super_admin` e `security_admin` só entram com TOTP: no primeiro login, a API devolve `{"status":"mfa_required","purpose":"enroll"}` e o cadastro (`POST /api/v1/auth/mfa/enroll` e `/confirm`) conclui o login. O token de recuperação é entregue só pelo CLI, no servidor; ele troca a senha e encerra as sessões, mas **não** desativa o MFA.

Agentes e eventos (ADR 0006). O enrolamento de agente exige um termo de autorização vigente, que só se registra pelo CLI, no servidor:

```powershell
uv run python -m app.cli record-authorization --reference "TERMO-001" --description "Rede de laboratório" --days 30
uv run python -m app.cli revoke-authorization --id <uuid>
uv run python -m app.cli purge-expired      # remove ingest_records (7 dias), idempotency_keys e tokens vencidos
```

Depois, pela API (administrador com MFA): `POST /api/v1/agents` (com `Idempotency-Key`) devolve um token de enrolamento de 24 h e uso único; o agente o troca por uma credencial em `POST /api/v1/agents/enroll` e envia lotes de até 100 eventos em `POST /api/v1/events` (`Authorization: Agent <credencial>`, `Idempotency-Key` obrigatória). A credencial e o token só aparecem uma vez. `rotate` e `revoke` trocam e cortam a credencial; a revogação vale na requisição seguinte.

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

## Agente Windows (fase 04a)

O agente (`agent/`) é só de telemetria: lê o Security log (EventIDs 4624, 4625, 4648, 4672, 4720 e 4732), guarda numa fila local limitada e envia ao Core por HTTPS com polling. Não recebe nem executa comandos do servidor. Desenho e decisões: [ADR 0007](docs/adr/0007-agente-windows-04a.md).

**Antes de rodar**, o Security log só é legível por administrador elevado ou por membro do grupo `Event Log Readers`. Para o caminho sem elevação, um administrador adiciona o usuário ao grupo e o usuário faz novo logon (o agente confere o acesso ao iniciar e diz o que falta):

```powershell
# Em PowerShell elevado (altera o sistema: faça de propósito)
net localgroup "Event Log Readers" $env:USERNAME /add
```

No Core, com termo de autorização registrado (ver acima), um administrador cria o agente (`POST /api/v1/agents`) e recebe o token de enrolamento. No host do agente:

```powershell
cd agent
uv sync
uv run python -m ares_agent enroll --server http://127.0.0.1:8000   # pede o token sem eco
uv run python -m ares_agent run                                      # Ctrl+C para parar
uv run python -m ares_agent status                                   # estado local, sem segredos
```

- `http://` só é aceito em loopback (`localhost`, `127.0.0.1`, `::1`); fora dele, `https://`. Não existe opção para desligar a verificação de certificado; para uma CA local, use `ca_file` no `config.toml`.
- `enroll --force` enrola de novo e **descarta** a fila e o marcador do agente anterior (avisa quantos eventos).
- O agente não herda proxy nem CA do ambiente (`HTTP_PROXY`, `SSL_CERT_FILE`).
- A credencial fica no Gerenciador de Credenciais do Windows, nunca em arquivo. O token de enrolamento nunca é argumento de linha de comando (iria para o histórico do shell).
- Estado, fila e log em `%LOCALAPPDATA%\ARES\agent` (`ARES_AGENT_HOME` muda a pasta). A coleta começa pelos eventos **novos**: o histórico do log não é lido.
- O agente coleta dado pessoal. Use só em máquina própria ou com autorização; a seção de privacidade e LGPD do complemento continua em branco de propósito. O que sai do host:

| EventID | Evento | Campos enviados (nada além destes) |
|---|---|---|
| 4624 | logon bem-sucedido | usuário, domínio, tipo de logon, estação, endereço de origem, processo |
| 4625 | logon falho | os mesmos, mais status e substatus |
| 4648 | logon com credencial explícita | usuário e domínio de origem, usuário e domínio alvo, processo |
| 4672 | privilégios especiais atribuídos | usuário, domínio |
| 4720 | conta criada | conta e domínio, quem criou e domínio |
| 4732 | membro adicionado a grupo | membro, grupo, quem alterou e domínio |

  Finalidade: telemetria de autenticação e de contas, para a detecção que virá em fases seguintes. Todos entram no Core como `personal`. **Quem lê:** quem tem a permissão `events.read` (ainda sem escopo por classificação). **Retenção:** o Core ainda não define prazo para eventos; a fila local guarda no máximo `queue_max_events` eventos (50 000 por padrão) e não é cifrada. Nunca se coleta linha de comando, senha, conteúdo de arquivo nem a mensagem em texto livre do evento.
- Testes: `uv run pytest` em `agent/` (não precisa de banco). O teste de integração contra o Core real fica em `backend/tests/test_agent_integration.py`.

## Stack proposta

Python/FastAPI, React + TypeScript, PostgreSQL. Detalhes e status de cada decisão na especificação.

## Licença

[Apache-2.0](LICENSE).
