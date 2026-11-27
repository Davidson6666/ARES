# ARES Core — Complemento à especificação (v1.2)

| Campo | Valor |
|---|---|
| Documento | Complemento à Especificação Geral e Arquitetura Core v1.1 |
| Versão | 1.2 (proposta de fechamento) |
| Data | 26 de novembro de 2026 |
| Status | Decisões da seção 1 confirmadas pelo autor em 26/11/2026. A seção 5 (privacidade e LGPD) está intencionalmente em branco. |
| Regra | Este complemento define especificação. Nenhuma linha de código de implementação está incluída. |

---

## 0. Correções de consistência (v1.1 → v1.2)

| Item | Problema na v1.1 | Correção na v1.2 |
|---|---|---|
| Versão | Cabeçalho e controle diziam 1.0. | Documento passa a ser 1.2; cabeçalho e controle atualizados ao mergear. |
| Nome | "Advanced Reconnaissance" sugere ofensiva. | Manter **ARES** como nome de trabalho, com expansão proposta **Adaptive Response & Event Security** (Provisória). |
| Event Bus × Event Ingress | Seção 3 trata o Event Bus como componente separado; seção 14.2 coloca o Event Ingress no Core. | O **Event Ingress** pertence ao Core e só valida e aceita eventos. O **Event Bus** é uma biblioteca interna do monólito (pacote `events`) que distribui, deduplica e encaminha. O Core nunca consome eventos para lógica de detecção. |
| Tabelas seção 7 × seção 16 | `configurations`, `investigations`, `module_status`, `mfa_factors` estavam sem modelo conceitual. | Todas reconciliadas na seção 2 deste complemento. |
| Códigos 400 × 422 | Sobreposição na seção 14.9. | Ver seção 3.4 abaixo. |
| Estimativa de fases | 8–14 meses pela soma, mas fase 01 parece otimista para trabalho manual. | Fase 01 mantida em 3–4 semanas **apenas para o escopo mínimo** da seção 21.13 (itens 1–4). Auditoria completa e eventos ficam em 01b, com estimativa de 2–3 semanas adicionais. |

---

## 1. Decisões das questões em aberto (seção 19.3)

**Status:** itens 1 a 7 confirmados pelo autor em 26/11/2026. Item 8 (retenção e dados sensíveis) fica em branco na seção 5.

| # | Questão | Decisão proposta | Justificativa | Revisar quando |
|---|---|---|---|---|
| 1 | Single-user ou multiusuário? | **Single-user no primeiro marco**, com schema de usuários, papéis e `user_roles` já completo. | Reduz escopo da fase 01 sem reescrever autorização depois. | Antes da fase 04 (identidade completa). |
| 2 | Primeiro agente: serviço ou processo do usuário? | **Processo executado pelo usuário** na fase 04a; Windows Service na fase 04b. | Facilita depuração e não exige privilégio elevado no início. | Ao validar permissões mínimas do agente. |
| 3 | Comunicação agente-servidor | **HTTPS com polling** e intervalo configurável. Canal persistente (WebSocket) só se a métrica de latência justificar. | Mais simples, atravessa firewall corporativo, fácil de auditar. | Quando a latência de alerta ultrapassar a meta de 30 s. |
| 4 | Modelo de sessão web | **Cookie `Secure`, `HttpOnly`, `SameSite=Strict`**, com token CSRF para operações mutáveis. Nada de token em `localStorage`. | Evita roubo de token por XSS, que é um risco real do dashboard (ver seção 4). | Se surgir cliente não-navegador consumindo a API com sessão humana. |
| 5 | Licença do código | **Apache-2.0** (confirmada). Verificar antes: Suricata e Wazuh são GPL; Zeek é BSD. Dependências GPL não devem ser vinculadas ao código do ARES sem análise. | Patente explícita e compatível com dependências permissivas. | Antes da primeira publicação pública. |
| 6 | Fontes de eventos Windows | Fase 04: **Security log** (4624, 4625, 4648, 4672, 4720, 4732) e **Sysmon** opcional para criação de processo (ID 1) e alteração de arquivo (ID 11). | Menor escopo, alto valor, já previsto em 4.4. | Ao definir o catálogo de eventos da fase 04. |
| 7 | Cookie × bearer token | Cookie (ver item 4). Bearer só para agentes, com credencial própria. | Separação clara entre humano e máquina. | — |
| 8 | Dados sensíveis e retenção | Deixado em branco (seção 5). | — | Preencher por quem usar o projeto em contexto real. |

---

## 2. Modelo de dados completo (adendo à seção 16)

### 2.1 Entidades que faltavam

| Entidade | Campos conceituais | Relações e regras |
|---|---|---|
| **UserRole** | user_id, role_id, granted_by, granted_at | PK composta (user_id, role_id). Ao remover papel, registrar auditoria. |
| **RolePermission** | role_id, permission_id | PK composta. Papel de sistema (Super Admin) não pode perder a permissão `roles.manage` pelo último administrador ativo. |
| **MfaFactor** | id, user_id, type (`totp`), secret_ref, status (`pending`, `active`, `revoked`), created_at, last_used_at | `secret_ref` aponta para cofre, nunca para o segredo em texto. Uma conta pode ter um fator ativo por tipo. |
| **RecoveryCode** | id, user_id, code_hash, used_at | Gerados em lote de 10. Hash com Argon2id. Ao regenerar, invalidar os anteriores. |
| **RecoveryToken** | id, user_id, token_hash, expires_at, used_at | Token de uso único, expiração de 15 minutos. Hash, nunca o token em texto. |
| **Session** (ampliada) | id, user_id, token_hash, created_at, last_seen_at, idle_expires_at, absolute_expires_at, revoked_at, ua_hash | Substitui o `session` da v1.1. `ua_hash` é hash do user-agent, sem armazenar o texto completo. IP não é persistido na sessão. |
| **Module** | id, name, version, contract_version, state, capabilities, last_heartbeat_at, registered_at | `state` ∈ {starting, healthy, degraded, unavailable, stopped}. Um módulo por instância. |
| **AgentCredential** | id, agent_id, credential_hash, issued_at, expires_at, revoked_at | Rotação cria nova linha; a antiga fica com `revoked_at` ou expira. Um agente pode ter no máximo uma credencial ativa. |
| **Configuration** | key, scope (`global`, `module:<id>`), value_json, version, updated_by, updated_at | Somente valores não secretos. Cada alteração gera linha em `audit_logs`. |
| **IdempotencyKey** | key, user_id (ou agent_id), request_hash, response_ref, created_at, expires_at | Retém a chave por 24 h. Mesma chave com `request_hash` diferente retorna 409. |
| **IngestRecord** | event_id (PK), received_at, source_id, outcome (`accepted`, `duplicate`, `rejected`) | Base de deduplicação da ingestão. Janela de retenção: 7 dias, depois arquivada. |
| **Investigation** | id, title, owner_id, status, opened_at, closed_at | **Não criar na fase 01.** Entra na fase 05 (Forensics). Listada aqui só para reconciliar a seção 7. |
| **ModuleStatusHistory** | id, module_id, from_state, to_state, observed_at, reason | Opcional na fase 01. Útil para o histórico exigido na seção 5 (Endpoint Manager). |

### 2.2 Regras de integridade adicionais

- E-mail único com índice **sem diferenciar maiúsculas** (normalizado para minúsculas no cadastro).
- Toda FK para `users` em `audit_logs` usa `ON DELETE RESTRICT`. Usuário nunca é apagado fisicamente; é desativado (`status = disabled`).
- Campos de status usam `CHECK` com lista fechada de valores.
- `audit_logs` ganha **campo de encadeamento** (`prev_hash`, `entry_hash`) para detectar alteração. Isso dá integridade verificável, mas não impede um administrador com acesso ao banco de reescrever a cadeia inteira. Para essa garantia é necessário armazenamento externo (ver 8.2).

---

## 3. Adendo à API (seção 15)

### 3.1 Autenticação por tipo de cliente

| Cliente | Mecanismo | Observação |
|---|---|---|
| Humano (dashboard) | Cookie de sessão + CSRF | Operações mutáveis exigem cabeçalho CSRF. |
| Agente | Credencial de agente (`Authorization: Agent <credencial>`) | Rotacionável. Nunca recebe permissão administrativa. |
| Engine interno | Identidade de serviço local | Em monólito, é chamada direta; quando houver separação de processo, usar credencial de serviço. |
| Público | Nenhuma | Apenas `/health`, rotas de auth e `POST /agents/enroll`, todas com rate limit. |
| Agente sem credencial (enrolamento) | Token de enrolamento (uso único, validade 24 h, guardado só como hash) | A rota `POST /agents/enroll` é pública porque o agente ainda não tem credencial; o token é a autenticação. |

### 3.2 Endpoints adicionados

| Método e rota | Finalidade | Permissão | Auth | Status de sucesso |
|---|---|---|---|---|
| `GET /api/v1/auth/sessions` | Listar sessões do próprio usuário | — | Humano | 200 |
| `DELETE /api/v1/auth/sessions/{id}` | Revogar sessão | próprio usuário ou `users.write` | Humano | 204 |
| `POST /api/v1/auth/mfa/enroll` | Iniciar cadastro de TOTP | — | Humano | 201 |
| `POST /api/v1/auth/mfa/confirm` | Confirmar TOTP com código válido | — | Humano | 200 |
| `DELETE /api/v1/auth/mfa` | Desativar MFA (exige reautenticação) | próprio usuário ou `users.write` | Humano | 204 |
| `POST /api/v1/auth/recovery/confirm` | Usar token de recuperação e definir nova senha | — | Público, com rate limit | 200 |
| `POST /api/v1/auth/recovery-codes` | Gerar novo lote de códigos de backup | — | Humano + reautenticação | 201 |
| `GET /api/v1/users` | Listar usuários (paginação por cursor) | `users.read` | Humano | 200 |
| `POST /api/v1/users` | Criar usuário | `users.write` | Humano | 201 |
| `PATCH /api/v1/users/{id}` | Alterar dados não sensíveis | `users.write` | Humano | 200 |
| `POST /api/v1/users/{id}/disable` | Desativar e revogar sessões | `users.write` | Humano | 200 |
| `PUT /api/v1/users/{id}/roles` | Substituir conjunto de papéis | `roles.manage` | Humano | 200 |
| `GET /api/v1/roles` | Listar papéis | `roles.manage` ou `users.read` | Humano | 200 |
| `POST /api/v1/roles` | Criar papel personalizado | `roles.manage` | Humano | 201 |
| `PUT /api/v1/roles/{id}/permissions` | Substituir permissões do papel | `roles.manage` | Humano | 200 |
| `GET /api/v1/permissions` | Catálogo de permissões | `roles.manage` | Humano | 200 |
| `POST /api/v1/modules/register` | Registrar módulo ou engine | `modules.configure` | Serviço interno | 201 |
| `POST /api/v1/modules/{id}/heartbeat` | Enviar heartbeat | — | Módulo autenticado | 202 |
| `GET /api/v1/modules/{id}` | Detalhe e histórico resumido | `modules.read` | Humano | 200 |
| `PATCH /api/v1/modules/{id}/config` | Alterar configuração não secreta | `modules.configure` | Humano | 200 |
| `POST /api/v1/agents` | Gerar token de enrolamento (uso único, validade 24 h) | `modules.configure` | Humano | 201 |
| `POST /api/v1/agents/enroll` | Trocar o token de enrolamento pela credencial do agente (exige termo de autorização vigente) | — | Público, autenticado pelo token de enrolamento, com rate limit | 201 |
| `POST /api/v1/agents/{id}/rotate` | Rotacionar credencial | `modules.configure` | Humano | 200 |
| `POST /api/v1/agents/{id}/revoke` | Revogar credencial | `modules.configure` | Humano | 200 |
| `POST /api/v1/events` | Ingestão de lote de eventos (máx. 100 por lote) | — | Agente (engine na fase de módulos) | 202 |
| `GET /api/v1/events/{event_id}` | Consultar evento | `events.read` | Humano | 200 |
| `GET /api/v1/config` | Configurações não secretas | `settings.manage` | Humano | 200 |
| `PATCH /api/v1/config/{key}` | Alterar configuração global | `settings.manage` | Humano + auditoria | 200 |

### 3.3 Regras transversais propostas

- **Bootstrap do administrador inicial:** feito por **comando de linha de comando** executado no servidor, não por endpoint HTTP. Não existe rota pública para criar o primeiro administrador.
- **Paginação por cursor** em todas as listas. Parâmetros: `limit` (padrão 50, máximo 200), `cursor` opaco.
- **Idempotency-Key:** obrigatório em `POST` de criação de usuário, agente e ingestão de eventos. Retenção de 24 h.
- **Ingestão de eventos (202):** a resposta lista o resultado por evento: `accepted`, `duplicate` ou `rejected`, com código de erro estável. Um lote parcialmente inválido não derruba os eventos válidos. Por isso, falha **de um evento** (acima de 64 KB, campo desconhecido no topo, campo inválido) vira `rejected` com código estável dentro do 202. Só falha **do lote** tem status próprio: corpo acima de 2 MB (413), JSON malformado (400), formato do lote inválido, lote vazio ou com mais de 100 eventos (422).
- **Campos de escrita:** lista explícita de campos aceitos em cada rota. Campos extras são rejeitados (proteção contra *mass assignment*, ver seção 4).

### 3.4 Códigos de erro — critério de uso

| Código | Quando usar |
|---|---|
| **400** Bad Request | A requisição não pode ser interpretada: JSON malformado, `Content-Type` incorreto, parâmetro de query desconhecido ou cursor inválido. |
| **422** Unprocessable Entity | O JSON é válido, mas um campo falha na validação de esquema (tipo, faixa, formato, campo obrigatório ausente, campo extra). |
| 401 | Credencial ausente ou inválida. |
| 403 | Identidade válida sem permissão. |
| 404 | Recurso inexistente **ou** fora do escopo do usuário (para não revelar existência). |
| 409 | Conflito de estado, versão ou reuso de `Idempotency-Key` com corpo diferente. |
| 413 | Corpo acima do limite (2 MB por lote). O limite de 64 KB por evento não gera 413: o evento vira `rejected` no 202 (seção 3.3). |
| 429 | Limite de taxa excedido, com cabeçalho `Retry-After`. |
| 503 | Dependência essencial (banco, por exemplo) indisponível. |

Erro padrão de corpo: `code` (estável, em snake_case), `message` (segura para exibir), `details` (lista opcional de campos, sem valores sensíveis), `request_id`.

---

## 4. Adendo ao modelo de ameaças (seção 17)

### 4.1 Ativos adicionados

| Ativo | Ameaça | Mitigação | Teste associado | Prioridade |
|---|---|---|---|---|
| **Dashboard (renderização de dados)** | XSS armazenado: log ou evento com HTML/JavaScript exibido na interface. | Escape por padrão no frontend; nenhum uso de HTML bruto a partir de dados; Content-Security-Policy restritiva; cookie `HttpOnly` limita o dano de um XSS. | Evento com `<script>` e payload de imagem em campo textual deve aparecer como texto. | **Alta** |
| **Ingestão de eventos** | Inundação (DoS) por agente comprometido ou laço de envio. | Limite por agente (taxa e tamanho), `429` com `Retry-After`, fila limitada com política de descarte documentada, alerta operacional de volume anômalo. | Carga com agente que excede o limite recebe `429` sem derrubar outros agentes. | **Alta** |
| **Evidências** | Alteração ou substituição de evidência. | Hash SHA-256 no momento da aquisição, registro em cadeia de custódia, armazenamento somente leitura para o próprio processo. | Alterar um byte da evidência deve falhar na verificação. | Média (fase 05) |
| **Recuperação de conta** | Abuso de token ou código de backup; enumeração de conta. | Token de uso único, 15 min, hash no banco; resposta idêntica para conta existente e inexistente; rate limit. | Token reutilizado retorna 401; tempo de resposta não distingue conta. | **Alta** |
| **MFA** | Reuso de código TOTP dentro da janela de validade. | Registrar o último código aceito por fator e rejeitar repetição. | Mesmo código duas vezes deve falhar na segunda. | Média |
| **Sessão** | Fixação de sessão (session fixation). | Novo identificador de sessão a cada login e a cada elevação de privilégio. | Sessão anterior ao login deixa de funcionar após o login. | **Alta** |
| **Credencial de agente** | Roubo de credencial do agente e uso em outro host. | Credencial vinculada ao enrolamento e ao identificador do host; rotação; revogação imediata; alerta em uso concorrente. | Credencial revogada retorna 401 imediatamente. | Alta |
| **Logs** | Injeção de quebra de linha ou de campos forjados em logs estruturados. | Serialização estruturada (JSON), escape de caracteres de controle. | Evento com `\n` gera uma única linha de log. | Média |
| **Atribuição em massa** | Cliente envia campo como `role` ou `status` e o servidor aceita. | Lista explícita de campos aceitos por rota; campos extras retornam 422. | `PATCH /users/{id}` com `roles` retorna 422. | **Alta** |
| **IDOR** | Acesso a recurso de outro usuário trocando o identificador. | Autorização por recurso e escopo em toda rota; 404 para recurso fora do escopo. | Usuário A não lê evento de escopo do usuário B. | **Alta** |
| **Timestamps** | Eventos com data falsa para burlar correlação temporal. | Campo `observed_at` definido pelo ARES no recebimento; `occurred_at` marcado como informado pela fonte; diferença acima de limite gera alerta de qualidade. | Evento com `occurred_at` no futuro distante é marcado. | Média |
| **Backups** | Vazamento de backup com hashes de senha e dados pessoais. | Backup criptografado, acesso restrito, teste periódico de restauração, retenção definida. | Backup não é legível sem a chave de restauração. | Alta |
| **Endpoint `/system/info`** | Vazamento de versões e caminhos internos. | Resposta mínima; apenas para `admin`; sem caminhos de sistema. | Usuário `viewer` recebe 403. | Média |

### 4.2 Itens que permanecem fora da proteção do Core

- Administrador malicioso ou conta administrativa comprometida com acesso ao host (seção 17.1). O Core reduz e registra, mas não elimina esse risco.
- Adulteração do banco por quem tem acesso direto ao servidor. Mitigação parcial pelo encadeamento de auditoria e, quando possível, cópia externa de logs.

---

## 5. Privacidade e LGPD

*Seção intencionalmente em branco. Este é um projeto de portfólio, sem operação real. Quem utilizar o ARES em contexto real deve preencher esta seção com a análise de privacidade, a base legal, os papéis dos envolvidos e a política de retenção aplicáveis ao seu caso, com apoio de profissional habilitado.*

### 5.1 Autorização do operador (requisito de produto)

- Termo de autorização registrado antes do primeiro agente ser enrolado.
- Bloqueio de enrolamento de agente sem termo vigente.
- Rastreio de qual autorização cobre cada agente.

## 6. Envelope de evento v1 (fecha a seção 6.1)

| Campo | Obrigatório | Tipo | Regra |
|---|---|---|---|
| `event_id` | Sim | UUID | Gerado pela fonte. Usado para deduplicação. |
| `event_type` | Sim | string | Formato `dominio.acao` em minúsculas, por exemplo `authentication.failure`. |
| `schema_version` | Sim | inteiro | Começa em 1. |
| `occurred_at` | Sim | RFC 3339 UTC | Informado pela fonte. Ex.: `2026-11-26T19:04:00Z`. |
| `observed_at` | Preenchido pelo ARES | RFC 3339 UTC | Momento do recebimento. Não pode ser enviado pela fonte. |
| `source.module` | Sim | string | `endpoint`, `network` etc. |
| `source.instance_id` | Sim | string | Identificador do agente ou engine. |
| `tenant_id` | Não | string | Reservado para uso multi-escopo. |
| `device_id` | Não | string | Identificador do dispositivo cadastrado. |
| `correlation_id` | Não | string | Para agrupar eventos relacionados. |
| `severity` | Não | enum | **Severidade do evento como informado pela fonte.** Não é a severidade do alerta (seção 4.3). |
| `data_classification` | Sim | enum | `public`, `internal`, `personal`, `sensitive`. Define retenção e acesso. |
| `data` | Sim | objeto | Payload específico do `event_type`. |

**Limites:** envelope completo até 64 KB; `data` até 16 KB; lote até 2 MB e 100 eventos.

**Compatibilidade:**
- Mudança **aditiva** (campo opcional novo) não exige nova versão de esquema.
- Mudança que remove ou altera o significado de campo exige `schema_version` incrementado e período de convivência de pelo menos 90 dias.
- Campo desconhecido em `data` é ignorado; campo desconhecido no topo do envelope rejeita o evento (`rejected` com código estável no 202, seção 3.3); no endpoint de eventos não derruba o lote.

**Observação:** o campo `severity` do evento e o de alerta são coisas diferentes. Esta distinção evita confundir "a fonte disse que é grave" com "o motor concluiu que é grave".

---

## 7. Ajustes na seção 21 (checklist)

- Itens 21.1, 21.2 e 21.6 podem ser marcados como **resolvidos provisoriamente** pelas decisões da seção 1, aguardando confirmação do autor.
- Item 21.8 ganha como novos itens: (a) termo de autorização de agente; (b) análise de privacidade (seção 5); (c) RIPD modelo.
- Critério de autorização da seção 21.12 é relaxado para o **marco 1 (fase 01a)**: não exige todas as fases de auditoria completa, apenas o escopo mínimo da seção 21.13 (itens 1 a 4).

---

## 8. Itens que dependem de decisão do autor ou de terceiros

### 8.1 Decisões do autor

- Confirmar ou substituir cada decisão marcada como **Provisória** (seção 1).
- Confirmar o nome e a expansão do projeto.
- Confirmar a licença.

### 8.2 Itens externos

- **Análise de privacidade e LGPD** (seção 5): deixada em branco; a ser preenchida por quem usar o projeto em contexto real.
- **Cópia externa de auditoria**, se a exigência de imutabilidade for forte. Escolha depende de onde o ARES será hospedado.

---

## 9. Histórico de versões (atualizado)

| Versão | Data | Alteração |
|---|---|---|
| 1.0 | 26/11/2026 | Especificação geral e arquitetura proposta do ARES Core. |
| 1.1 | 26/11/2026 | Checklist de pré-implementação, critérios para iniciar e primeira iteração. |
| 1.2 | 26/11/2026 | Correções de consistência; decisões provisórias para as questões em aberto; modelo de dados completo; adendo à API; adendo ao modelo de ameaças; seção de privacidade e LGPD deixada em branco; envelope de evento v1; ajustes ao checklist. |
| 1.2.1 | 27/11/2026 | Alinhada ao ADR 0006 (fase 01b): `POST /agents/enroll` público, autenticado pelo token de enrolamento (3.1 e 3.2); falha por evento vira `rejected` no 202, com 413/422 só para falha do lote (3.3, 3.4 e 6); `POST /events` só com agente, engine na fase de módulos (3.2). |
