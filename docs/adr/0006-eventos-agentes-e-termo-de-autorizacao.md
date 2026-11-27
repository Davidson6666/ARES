# ADR 0006 — Ingestão de eventos, agentes e termo de autorização

| Campo | Valor |
|---|---|
| Status | Proposto |
| Data | 2026-11-27 |
| Revisar até | 2026-12-11 |

## Contexto

- Fase 01b (CLAUDE.md, seção 11): auditoria completa e eventos. Itens 6 e 7 da seção 21.13 da v1.1: contrato e ingestão inicial de eventos; testes de integração e recuperação do Core.
- Escopo escolhido pelo autor em 27/11/2026: **eventos**, **agentes e credenciais** e **termo de autorização do operador**. Ficam fora da 01b: rotas de administração de usuários e papéis, e módulos e configuração.
- Complemento v1.2: autenticação do agente por `Authorization: Agent <credencial>` (3.1); rotas `POST /agents`, `rotate`, `revoke`, `POST /events` e `GET /events/{event_id}` (3.2); `Idempotency-Key` obrigatório em ingestão e criação de agente, retenção de 24 h (3.3); códigos 400, 413, 422, 429 (3.4); modelo `AgentCredential`, `IdempotencyKey` e `IngestRecord` (2.1); envelope de evento v1 (seção 6 do complemento).
- CLAUDE.md: Event Ingress pertence ao Core e só valida e aceita; o Event Bus (pacote `events`) distribui, deduplica e encaminha; o Core **nunca** consome eventos para lógica de detecção (seção 5). Seção 9.4: termo de autorização antes do primeiro enrolamento.
- Testes de aceitação que este ADR deve cobrir (seção 9.2): inundação por agente (429 sem derrubar outros), credencial revogada (401 imediato), IDOR em evento (404), XSS armazenado (evento com `<script>` volta como dado), quebra de linha em log, timestamp futuro marcado, atribuição em massa.

## Decisão

### Confirmado pelo autor em 27/11/2026

| Item | Decisão |
|---|---|
| Escopo | Eventos, agentes e credenciais, termo de autorização. |
| Termo de autorização | Entra agora: `POST /agents` é bloqueado sem termo vigente, e cada agente guarda qual termo o cobre. |
| Persistência de eventos | Tabela `events` no PostgreSQL, com `data` em JSONB (até 16 KB) e `observed_at` definido pelo servidor. |

### Proposto

**Agentes e credenciais**

| Item | Decisão | Motivo |
|---|---|---|
| Tabelas | `agents` (id, nome, módulo, `tenant_id`, `status` ∈ {pending, active, revoked}, `authorization_id`, criado por, `last_seen_at`, `revoked_at`), `agent_enrollment_tokens` (hash, uso único, 24 h), `agent_credentials` (hash, `issued_at`, `expires_at`, `revoked_at`; no máximo uma ativa por agente, por índice único parcial). | Complemento 2.1 e CLAUDE.md 6.1. |
| Enrolamento | `POST /api/v1/agents` (humano, `modules.configure`, `Idempotency-Key`) cria o agente `pending` e devolve um token de enrolamento **uma única vez**. **Rota nova** `POST /api/v1/agents/enroll` (pública, rate limit por IP): o agente apresenta o token e recebe a credencial **uma única vez**. | O complemento define o token de enrolamento mas não a rota em que o agente o troca por credencial. |
| Credencial | `ares_agent_<id do agente>.<32 bytes aleatórios em base64url>`. No banco fica o SHA-256 do segredo. Cabeçalho `Authorization: Agent <credencial>`. O agente é achado pelo id embutido e o segredo é comparado em tempo constante. | 256 bits aleatórios: SHA-256 basta (sem Argon2, que custaria memória a cada lote). |
| Rotação e revogação | `rotate` revoga a credencial anterior no mesmo instante e emite outra (no máximo uma ativa). `revoke` revoga o agente e a credencial. A autenticação consulta o banco a cada requisição, sem cache: 401 imediato. | Teste 9.2: credencial revogada, 401 imediato. |
| Agente nunca é administrador | A autenticação de agente produz um contexto próprio, sem papéis nem permissões. Rotas de humano recusam cookie e credencial de agente trocados. | Complemento 3.1. |
| Vínculo de origem | O envelope só é aceito se `source.instance_id` for o id do agente, `source.module` for o módulo do agente e, se o envelope trouxer `tenant_id`, ele for o do agente. Divergência rejeita o evento (`source_mismatch`, `tenant_mismatch`). | Um agente comprometido não forja eventos de outra origem. |
| Escopo (`tenant_id`) | Novas colunas `users.tenant_id` e `agents.tenant_id`, ambas anuláveis. Usuário com `tenant_id` nulo lê eventos de qualquer escopo; usuário com valor lê só os do seu escopo. Fora do escopo: 404. | Teste 9.2: IDOR em evento. Complemento seção 6 reserva `tenant_id`. |
| Auditoria | `agent.enrollment_token_issued`, `agent.enrolled`, `agent.rotated`, `agent.revoked` e `authorization.recorded` (CLI, ator `system`). A ingestão em si **não** é auditada por requisição (volume): fica em log operacional e métricas. | ADR 0004: sob volume, log, não auditoria. |

**Termo de autorização do operador (CLAUDE.md 9.4)**

| Item | Decisão |
|---|---|
| Tabela | `operator_authorizations` (id, referência, descrição, `valid_from`, `valid_until`, `recorded_at`, `revoked_at`). |
| Registro | Só pelo CLI, no servidor: `record-authorization --reference ... --description ... --days N` e `revoke-authorization --id ...`. Auditados como `system`. Não há rota HTTP. |
| Bloqueio | `POST /agents` exige `authorization_id` de um termo vigente (dentro da validade e não revogado); senão, 409 `authorization_required`. O enrolamento (`/agents/enroll`) reconfere o termo: termo revogado ou vencido entre a criação e o enrolamento impede o enrolamento. |
| Rastreio | `agents.authorization_id` guarda qual termo cobre cada agente. |

**Contrato e ingestão de eventos**

| Item | Decisão | Motivo |
|---|---|---|
| Rota | `POST /api/v1/events`, lote de até 100 eventos, autenticação de agente, `Idempotency-Key` obrigatório. Resposta **202** com uma lista de resultados por evento: `accepted`, `duplicate` ou `rejected`, com `error_code` estável. Lote parcialmente inválido não derruba os eventos válidos. | Complemento 3.2 e 3.3. |
| Limites | Corpo do lote até 2 MB: acima, **413** do lote inteiro (medido durante a leitura, sem carregar tudo na memória). Evento acima de 64 KB, ou `data` acima de 16 KB: aquele evento é rejeitado (`event_too_large`, `data_too_large`). Mais de 100 eventos: **422** `batch_too_large`. | Complemento 3.4 e seção 6. A diferença entre 413 do lote e rejeição por evento é decisão deste ADR. |
| Validação do envelope | Campos do complemento, seção 6. `observed_at` enviado pela fonte: evento rejeitado (`observed_at_not_allowed`). Campo desconhecido no topo: rejeitado (`unknown_field`). Campo desconhecido em `data`: ignorado e preservado. `schema_version` ≠ 1: `unsupported_schema_version`. `event_type` fora do formato `dominio.acao` minúsculo: `invalid_event_type`. | Seção 6 e regras de compatibilidade do complemento. |
| Timestamp | `occurred_at` informado pela fonte. Mais de 5 minutos no futuro: o evento é **aceito e marcado** (`flags` contém `occurred_at_future`). | Teste 9.2: timestamp futuro. |
| Deduplicação | `events.event_id` é a chave primária (INSERT ... ON CONFLICT DO NOTHING). Mesmo `event_id` do mesmo agente: `duplicate`. De outro agente: `rejected` com `event_id_conflict`. | Complemento 2.1: a base é o `event_id`. |
| `ingest_records` | `event_id`, `received_at`, `source_id`, `outcome`, `error_code`. Guarda o último resultado de cada `event_id` visto (inclusive rejeitados com id válido). Retenção de 7 dias. | Complemento 2.1. |
| Idempotency-Key | Tabela `idempotency_keys` com chave por (principal, chave), hash do pedido, status e corpo da resposta, validade de 24 h. Mesma chave e mesmo pedido: repete a resposta guardada. Mesma chave e pedido diferente: **409**. Duas requisições simultâneas com a mesma chave são serializadas (`pg_advisory_xact_lock`). | Complemento 3.3. |
| Atomicidade | Um lote é uma transação: eventos aceitos, `ingest_records` e `idempotency_keys` entram juntos ou nenhum entra. Falha do banco é 503, e o agente reenvia com a mesma chave. | Recuperação: sem estado parcial. |
| Limite por agente | Em memória, janela deslizante por agente: requisições por minuto e eventos por minuto (valores configuráveis). Excedido: **429** com `Retry-After`. Cada agente tem o seu limite. | Teste 9.2: inundação por agente. |
| Pacote `events` | O Ingress (Core) valida o envelope e entrega os eventos aceitos à interface `EventBus.publish`. A implementação inicial grava na tabela `events`. Nenhum consumidor existe ainda, e o Core não se inscreve no bus. | CLAUDE.md, seção 5. |
| Leitura | `GET /api/v1/events/{event_id}`, permissão `events.read`. `data` é devolvido como dado JSON, nunca como HTML. | Teste 9.2: XSS armazenado. |
| Campos de `events` | `event_id`, `event_type`, `schema_version`, `occurred_at`, `observed_at`, `source_module`, `source_instance_id`, `agent_id`, `tenant_id`, `device_id`, `correlation_id`, `severity`, `data_classification`, `data`, `flags`. | v1.1, seção 16 (Event) e complemento, seção 6. |
| Manutenção | Comando `purge-expired` do CLI remove `ingest_records` e `idempotency_keys` vencidos. | Retenções do complemento. |

**Item 7 da seção 21.13 (integração e recuperação)**

| Item | Decisão |
|---|---|
| Recuperação | Testes de que o Core volta a atender depois de o banco derrubar as conexões (`pg_terminate_backend`) e depois de reinício do processo: sessões e eventos persistem, e o lote interrompido não deixa estado parcial. |
| Integração | Um teste de ponta a ponta: administrador cadastra o TOTP, registra o termo, cria o agente, o agente se enrola, envia um lote, e o evento é lido por `GET /events/{id}` e aparece na trilha de auditoria. |

## Em aberto

| Item | Alternativas | Risco de adiar |
|---|---|---|
| Modelo de escopo (`tenant_id`) | Os dois campos de escopo acima, ou uma tabela de escopos por usuário | O escopo mínimo proposto só distingue "tudo" de "um escopo". Revisar antes do multiusuário real. |
| Vínculo da credencial ao host (v1.1, 17; complemento 4.1) | Guardar `host_id` no enrolamento e alertar sobre uso concorrente | A 04a define como o host se identifica. |
| Eventos muito antigos | Marcar `occurred_at` com mais de N dias no passado | Pode distorcer correlação temporal futura. |
| Dead-letter, retentativas com backoff e fila limitada (v1.1, 6.2) | Implementar com os primeiros consumidores | Não há consumidores ainda; sem eles o item não tem o que testar. |
| Particionamento da tabela `events` | Particionar por tempo quando houver volume medido (v1.1, 7.1) | Reescrever a tabela depois custa mais. |
| Rate limit com vários workers | Contador em PostgreSQL ou Redis | Igual ao login (ADR 0003). |
| Retenção de `events` por `data_classification` | Seção 5 do complemento (LGPD), em branco | A tabela cresce sem limite. |
| Revogar um agente por rota de usuário `users.write` e administração de usuários e papéis | Fica para uma fase seguinte (fora do escopo escolhido) | Não há rota para o administrador gerir usuários além do bootstrap. |

## Consequências

- A tabela `events` guarda dados enviados por agentes: tratar como **conteúdo não confiável** (CLAUDE.md, 9.1). A API devolve JSON; o escape fica a cargo do frontend.
- Credencial de agente vazada permite enviar eventos como aquele agente até a revogação. O limite por agente e o vínculo de origem reduzem o dano.
- O enrolamento passa a depender de um termo registrado no servidor.
- A auditoria cresce só com eventos de gestão de agentes, não com a ingestão.
- Nova migração (0005) com várias tabelas e duas colunas novas em `users` e `agents`.
