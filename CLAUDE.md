# CLAUDE.md — ARES

Plataforma modular de ciberdefesa **defensiva**: painel web + agentes Windows/Linux.
Nome de trabalho: **ARES**. Expansão proposta (provisória): *Adaptive Response & Event Security*.

Projeto de portfólio, sem operação real. Repositório ainda sem código de funcionalidade.

## 1. Estado atual

- **Confirmado:** especificação escrita. Especificação Geral v1.1 em `docs/ARES_Especificacao_Geral_e_Arquitetura_Core_v1.1.md` (conversão do `.docx` original, mantido em `docs/`; conferida palavra a palavra em 26/11/2026; leia o `.md`) e Complemento v1.2 em `docs/ARES_Core_v1.2_Complemento.md`.
- **Não implementado:** nenhum código de funcionalidade. Não marque nada como implementado sem código existente ou teste passando.
- **Repositório:** Git iniciado em 26/11/2026, branch `main`, remoto `origin` = `https://github.com/Davidson6666/ARES.git`. Existem `README.md`, `LICENSE` (Apache-2.0), `.gitignore`, `.gitattributes`, `docs/ENVIRONMENT.md` e `docs/adr/` (vazio).
- **Escopo da fase 01a:** seção 21.13 da v1.1, itens 1 a 4 (ver seção 11 deste arquivo).
- **Banco de desenvolvimento:** PostgreSQL em contêiner Docker, escolhido pelo autor em 26/11/2026. ADR pendente (`/new-adr`, executado pelo autor).

## 2. Fontes de verdade

- Ordem: **Complemento v1.2** prevalece sobre a **Especificação Geral v1.1** em caso de conflito (o próprio complemento, seção 0, corrige a v1.1).
- Consulte os documentos antes de qualquer decisão de arquitetura, modelo de dados, API, segurança ou escopo de fase.
- `docs/ENVIRONMENT.md` registra versões reais de ferramentas. Não assuma versões; use as registradas.
- `docs/adr/` registra decisões arquiteturais. Decisão difícil de reverter exige ADR antes da implementação.

## 3. Regras de trabalho

- A implementação é manual, feita pelo autor. Não escreva código de funcionalidade sem pedido explícito. Quando pedido, entregue trechos pequenos e explique o porquê.
- Documentação antes de implementação. Mudança de arquitetura, dados, API ou segurança atualiza o documento correspondente. Decisão vira ADR.
- Toda mudança relevante entra no histórico de versões do documento afetado.
- Separe sempre: **confirmado**, **proposto**, **em aberto**.
- Decisão em aberto não vira decisão silenciosa. Registre: o que falta saber, as alternativas, o risco de adiar e a data de revisão.
- Ao fazer mudanças, aponte o que está incerto em vez de inventar detalhes.
- Ao terminar uma tarefa: liste o que foi feito, o que não foi verificado e o que ficou em aberto.

## 4. Decisões

### 4.1 Confirmadas pelo autor em 26/11/2026 (complemento, seção 1)

| # | Decisão |
|---|---|
| 1 | **Single-user no primeiro marco**, com schema de usuários, papéis e `user_roles` completo (RBAC). |
| 2 | Primeiro agente é **processo executado pelo usuário** (fase 04a); Windows Service depois (fase 04b). |
| 3 | Comunicação agente-servidor por **HTTPS com polling** e intervalo configurável. WebSocket só se a latência justificar (meta de alerta: 30 s). |
| 4 | Sessão web por **cookie `Secure`, `HttpOnly`, `SameSite=Strict`**, com token CSRF em operações mutáveis. **Nada de token em `localStorage`.** |
| 5 | Licença **Apache-2.0**. Dependências GPL (Suricata, Wazuh) não vinculadas ao código sem análise. Zeek é BSD. |
| 6 | Eventos Windows na fase 04: Security log (4624, 4625, 4648, 4672, 4720, 4732). Sysmon opcional (ID 1 e ID 11). |
| 7 | Cookie para humano; bearer somente para agentes, com credencial própria. |

### 4.2 Registradas apenas no CLAUDE.md anterior (confirmar)

- Stack: Python/FastAPI, React + TypeScript, PostgreSQL. Redis opcional. Rust só com justificativa.
- Monólito modular como primeira arquitetura.

**Pendência:** o complemento (seções 7 e 8.1) chama as decisões de "provisórias", mas a seção 1 diz "confirmadas". Confirme com o autor qual status vale. Até lá, trate como confirmadas, sem reabrir.

### 4.3 Em aberto

| Item | Alternativas | Risco de adiar | Revisar |
|---|---|---|---|
| Privacidade e LGPD (seção 5 do complemento) | Preencher por quem usar em contexto real | Sem análise, o ARES não pode operar em contexto real | Antes de qualquer uso real |
| Retenção e dados sensíveis (item 8 da seção 1) | Em branco | Idem | Idem |
| Nome e expansão do projeto | Manter ARES; expansão provisória | Baixo | Antes da publicação |
| Verificação de licença das dependências | Análise por dependência | Vincular GPL sem análise | Antes da primeira publicação pública |

**Não preencha a seção 5 do complemento sem o autor pedir.**

## 5. Arquitetura

- **Monólito modular.** Módulos separados por pacote, comunicação interna por interfaces.
- **Core:** autenticação, autorização, usuários, papéis, módulos, agentes, configurações, auditoria e **Event Ingress**.
- **Event Ingress** (pertence ao Core): valida e aceita eventos. Não interpreta nem decide.
- **Event Bus** (pacote `events`, biblioteca interna): distribui, deduplica e encaminha eventos.
- **Regra:** o Core **nunca** consome eventos para lógica de detecção.
- **Agentes** Windows/Linux: enviam eventos ao servidor por HTTPS com polling. Registram heartbeat.
- **Engines** (ex.: rede): entram como módulos registrados, com credencial de serviço quando houver separação de processo.

## 6. Modelo de dados

### 6.1 Entidades

| Entidade | Pontos-chave |
|---|---|
| `users` | E-mail único sem diferenciar maiúsculas (normalizado para minúsculas). Nunca apagar fisicamente; usar `status = disabled`. |
| `roles`, `permissions` | Catálogo de permissões. |
| `user_roles` | PK composta (`user_id`, `role_id`); `granted_by`, `granted_at`. Remoção gera auditoria. |
| `role_permissions` | PK composta. O último administrador ativo não pode perder `roles.manage`. |
| `mfa_factors` | `type` = `totp`; `secret_ref` aponta para cofre, nunca o segredo em texto; `status` ∈ {pending, active, revoked}; uma conta tem um fator ativo por tipo. |
| `recovery_codes` | Lote de 10; hash Argon2id; regerar invalida os anteriores. |
| `recovery_tokens` | Hash do token; uso único; expira em 15 min. |
| `sessions` | `token_hash`, `last_seen_at`, `idle_expires_at`, `absolute_expires_at`, `revoked_at`, `ua_hash`. **IP não é persistido.** Novo identificador a cada login e elevação de privilégio. |
| `modules` | `state` ∈ {starting, healthy, degraded, unavailable, stopped}; `contract_version`; `capabilities`; `last_heartbeat_at`. |
| `module_status_history` | Opcional na fase 01. |
| `agent_credentials` | Rotação cria nova linha; no máximo uma credencial ativa por agente; `revoked_at` ou expiração. |
| `configurations` | `scope` ∈ {global, module:<id>}; `value_json`; `version`. Só valores não secretos. Toda alteração gera linha em `audit_logs`. |
| `idempotency_keys` | Retenção 24 h. Mesma chave com `request_hash` diferente → 409. |
| `ingest_records` | `event_id` (PK); `outcome` ∈ {accepted, duplicate, rejected}; retenção 7 dias. |
| `audit_logs` | Campos `prev_hash`, `entry_hash` (encadeamento). FK para `users` com `ON DELETE RESTRICT`. |
| `investigations` | **Não criar na fase 01.** Entra na fase 05. |

### 6.2 Regras de integridade

- Campos de status com `CHECK` de lista fechada.
- Encadeamento de auditoria detecta alteração, mas não impede quem tem acesso direto ao banco de reescrever a cadeia inteira. Garantia forte exige cópia externa (item externo, ver 9.2).

## 7. API

### 7.1 Autenticação por tipo de cliente

| Cliente | Mecanismo |
|---|---|
| Humano (painel) | Cookie de sessão + CSRF em mutações. |
| Agente | `Authorization: Agent <credencial>`. Rotacionável. **Nunca recebe permissão administrativa.** |
| Engine interno | Identidade de serviço local. |
| Público | Apenas `/health` e rotas de auth com rate limit. |

### 7.2 Regras transversais

- **Bootstrap do administrador:** por comando de linha de comando no servidor. **Não existe rota HTTP pública para criar o primeiro administrador.**
- **Paginação por cursor** em todas as listas: `limit` (padrão 50, máximo 200), `cursor` opaco.
- **`Idempotency-Key`** obrigatório em `POST` de criação de usuário, agente e ingestão.
- **Ingestão (202):** resposta lista o resultado por evento (`accepted`, `duplicate`, `rejected`) com código de erro estável. Lote parcialmente inválido não derruba os eventos válidos.
- **Atribuição em massa proibida:** lista explícita de campos aceitos por rota. Campo extra → 422.
- **Bootstrap, enumeração e recuperação:** resposta de recuperação idêntica para conta existente e inexistente.

### 7.3 Endpoints (referência do complemento, seção 3.2)

Prefixo `/api/v1`. Principais:

| Método e rota | Permissão | Sucesso |
|---|---|---|
| `GET /auth/sessions`, `DELETE /auth/sessions/{id}` | próprio usuário ou `users.write` | 200 / 204 |
| `POST /auth/mfa/enroll`, `POST /auth/mfa/confirm`, `DELETE /auth/mfa` | humano (desativar exige reautenticação) | 201 / 200 / 204 |
| `POST /auth/recovery/confirm` | público, rate limit | 200 |
| `POST /auth/recovery-codes` | humano + reautenticação | 201 |
| `GET/POST /users`, `PATCH /users/{id}`, `POST /users/{id}/disable` | `users.read` / `users.write` | 200 / 201 |
| `PUT /users/{id}/roles` | `roles.manage` | 200 |
| `GET/POST /roles`, `PUT /roles/{id}/permissions`, `GET /permissions` | `roles.manage` (GET de roles aceita `users.read`) | 200 / 201 |
| `POST /modules/register` | serviço interno, `modules.configure` | 201 |
| `POST /modules/{id}/heartbeat` | módulo autenticado | 202 |
| `GET /modules/{id}`, `PATCH /modules/{id}/config` | `modules.read` / `modules.configure` | 200 |
| `POST /agents` (token de enrolamento, uso único, 24 h), `POST /agents/{id}/rotate`, `POST /agents/{id}/revoke` | `modules.configure` | 201 / 200 |
| `POST /events` (máx. 100 por lote) | agente ou engine | 202 |
| `GET /events/{event_id}` | `events.read` | 200 |
| `GET /config`, `PATCH /config/{key}` | `settings.manage` (PATCH com auditoria) | 200 |

### 7.4 Códigos de erro

| Código | Uso |
|---|---|
| 400 | Requisição não interpretável: JSON malformado, `Content-Type` errado, query desconhecida, cursor inválido. |
| 401 | Credencial ausente ou inválida. |
| 403 | Identidade válida sem permissão. |
| 404 | Inexistente **ou** fora do escopo (não revelar existência). |
| 409 | Conflito de estado ou versão; reuso de `Idempotency-Key` com corpo diferente. |
| 413 | Acima do limite: 64 KB por evento; 2 MB por lote. |
| 422 | JSON válido, mas falha no esquema (tipo, faixa, formato, obrigatório, campo extra). |
| 429 | Limite de taxa, com `Retry-After`. |
| 503 | Dependência essencial (ex.: banco) indisponível. |

Corpo de erro padrão: `code` (snake_case, estável), `message` (segura para exibir), `details` (opcional, sem valores sensíveis), `request_id`.

## 8. Envelope de evento v1

| Campo | Obrigatório | Regra |
|---|---|---|
| `event_id` | Sim | UUID gerado pela fonte; base da deduplicação. |
| `event_type` | Sim | `dominio.acao`, minúsculas (ex.: `authentication.failure`). |
| `schema_version` | Sim | Inteiro, começa em 1. |
| `occurred_at` | Sim | RFC 3339 UTC, informado pela fonte. |
| `observed_at` | Não enviar | Preenchido pelo ARES no recebimento. Fonte que enviar → rejeitar. |
| `source.module`, `source.instance_id` | Sim | Módulo e identificador do agente/engine. |
| `data_classification` | Sim | `public`, `internal`, `personal`, `sensitive`. Define retenção e acesso. |
| `severity` | Não | **Severidade informada pela fonte.** Não é a severidade do alerta. |
| `tenant_id`, `device_id`, `correlation_id` | Não | Ver complemento seção 6. |
| `data` | Sim | Payload do `event_type`. Limite 16 KB. |

- Envelope até 64 KB; lote até 2 MB e 100 eventos.
- Campo novo opcional: aditivo, sem nova versão.
- Remover ou mudar significado: incrementar `schema_version` e manter convivência de 90 dias.
- Campo desconhecido em `data`: ignorar. Campo desconhecido no topo: 422.

## 9. Segurança

### 9.1 Regras gerais

- Nunca commitar segredos. `.env` fora do Git; só `.env.example` com valores fictícios.
- Senhas com Argon2id. Nunca registrar senha, token, segredo MFA ou chave em logs, erros ou respostas.
- Autorização sempre validada no backend. Esconder botão na interface não é controle de acesso.
- Não criar criptografia própria. Usar bibliotecas consolidadas.
- Não adicionar funcionalidade que execute comandos arbitrários em endpoints, acesse dispositivos sem autorização ou teste contra sistemas de terceiros.
- Dados importados e indicadores externos são **conteúdo não confiável**. Nunca renderizar como HTML. Escape por padrão; CSP restritiva.
- Logs estruturados em JSON; caracteres de controle escapados (evita injeção de linha).
- Endpoint de informações do sistema: resposta mínima, só para `admin`, sem caminhos internos.

### 9.2 Testes de segurança obrigatórios (complemento seção 4.1)

Cada mitigação tem teste de aceitação. Não marque como concluída sem o teste passando.

| Ameaça | Teste de aceitação | Prioridade |
|---|---|---|
| XSS armazenado | Evento com `<script>` aparece como texto. | Alta |
| Inundação por agente | Agente acima do limite recebe 429 sem derrubar outros. | Alta |
| Reuso de token de recuperação | Token reutilizado → 401; tempo de resposta não distingue conta. | Alta |
| Fixação de sessão | Sessão anterior ao login deixa de funcionar. | Alta |
| Atribuição em massa | `PATCH /users/{id}` com `roles` → 422. | Alta |
| IDOR | Usuário A não lê evento de escopo de B (404). | Alta |
| Credencial de agente revogada | 401 imediato. | Alta |
| Backup | Não legível sem chave de restauração. | Alta |
| Reuso de código TOTP | Mesmo código duas vezes: a segunda falha. | Média |
| Evidência alterada (fase 05) | Alterar um byte falha na verificação. | Média |
| Quebra de linha em log | Evento com `\n` gera uma linha. | Média |
| Timestamp futuro | `occurred_at` distante no futuro é marcado. | Média |
| `/system/info` por `viewer` | 403. | Média |

### 9.3 Fora da proteção do Core

- Administrador malicioso ou conta administrativa comprometida com acesso ao host. O Core reduz e registra, não elimina.
- Adulteração do banco por quem tem acesso direto ao servidor. Mitigação parcial pela cadeia de auditoria.

### 9.4 Operador e agentes (requisito de produto, proposto)

- Termo de autorização registrado **antes** do primeiro enrolamento de agente.
- Bloquear enrolamento sem termo vigente.
- Rastrear qual autorização cobre cada agente.

## 10. Convenções

- **Idioma:** documentação e comentários de decisão em português (pt-BR). Caminhos, nomes de endpoint e identificadores de código em inglês, como na especificação.
- **Branches:** `feature/*`, `fix/*`, `refactor/*`, `docs/*`. `main` é a versão estável.
- **Commits:** prefixos `feat:`, `fix:`, `test:`, `security:`, `docs:`. Commits pequenos e rastreáveis.
- **Erros de API:** formato da seção 7.4 (400 malformado; 422 validação).

## 11. Fases

| Fase | Escopo |
|---|---|
| 01a | Marco 1: escopo mínimo da seção 21.13 (itens 1 a 4). Estimativa 3–4 semanas. (1) Repositório, estrutura mínima, ambiente e documentação base. (2) Core inicial com configuração e `/health`/`/ready`. (3) Conexão PostgreSQL e primeira migração testada. (4) Identidade, login, sessão e autorização mínima. |
| 01b | Auditoria completa e eventos. Mais 2–3 semanas. |
| 04a | Primeiro agente como processo do usuário. |
| 04b | Windows Service. |
| 05 | Forensics (investigações e evidências). |

Antes de iniciar uma fase: confirme o escopo na seção 21 da especificação. Não avance para fase de auditoria completa sem o autor pedir.

## 12. Ambiente

- Shell principal: PowerShell (Windows 11). Bash também disponível.
- Verificação de ambiente é somente leitura: edição do Windows, CPU, RAM, disco, virtualização, WSL 2, Docker Desktop, versões de Python, Node.js, Git, PostgreSQL. Grave em `docs/ENVIRONMENT.md`; marque "não encontrado" o que faltar.
- **Não instale nem altere configurações do sistema sem confirmação do autor.**

## 13. Skills, plugins e MCP

- Use skills só quando a tarefa exigir.
- Para sugerir automações, use `claude-code-setup` (`claude-automation-recommender`). Apresente ao autor antes de instalar.
- **Não instale skill, plugin ou MCP sem confirmação explícita do autor.**
- Candidatos prováveis, a confirmar: revisão de Markdown, Pytest, Vitest/Playwright (quando houver frontend).
