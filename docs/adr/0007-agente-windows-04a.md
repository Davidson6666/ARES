# ADR 0007 — Primeiro agente Windows (fase 04a)

| Campo | Valor |
|---|---|
| Status | Proposto |
| Data | 2026-11-27 |
| Revisar até | 2026-12-11 |

## Contexto

- Fase 04a (CLAUDE.md, seção 11): primeiro agente, como **processo executado pelo usuário**. Windows Service fica para a 04b.
- Escopo escolhido pelo autor em 27/11/2026: abrir a 04a depois de concluída a fase 01 (os 7 itens da seção 21.13 estão na `main`). Administração de usuários, papéis, módulos e configuração (01c) ficam para depois.
- O Core já tem o lado servidor (ADR 0006): termo de autorização, `POST /agents`, `POST /agents/enroll`, rotação, revogação, `POST /events` (lote de até 100, resultado por evento no 202, `Idempotency-Key`) e `GET /events/{event_id}`.
- Complemento v1.2, seção 1: itens 2 (processo do usuário), 3 (HTTPS com polling, intervalo configurável) e 6 (fonte: Security log 4624, 4625, 4648, 4672, 4720, 4732; Sysmon opcional, IDs 1 e 11).
- Especificação v1.1, seção 4.4: agente de telemetria e monitoramento; comunicação autenticada e criptografada; fila local limitada, com proteção contra crescimento ilimitado; privilégios mínimos; transparência sobre os dados coletados. **Sem execução remota arbitrária, persistência oculta, evasão ou ações destrutivas.**
- Seção 17.2 da v1.1: coletar só o necessário e documentar o que o agente coleta, por quê, por quanto tempo e quem consulta.
- CLAUDE.md 9.1 e 9.4: o agente nunca recebe permissão administrativa; termo de autorização vigente antes do enrolamento.
- Testes de aceitação que este ADR deve cobrir (CLAUDE.md 9.2): inundação por agente (429 sem derrubar outros), credencial revogada (401 imediato), quebra de linha em log, timestamp futuro.

## Decisão

### Confirmado (complemento e CLAUDE.md)

- Processo do usuário, não serviço.
- HTTPS com polling, intervalo configurável; sem canal persistente.
- Credencial própria do agente (`Authorization: Agent <credencial>`), sem papéis nem permissões de humano.
- Fontes: Security log, IDs 4624, 4625, 4648, 4672, 4720 e 4732.
- Agente só de telemetria: não recebe nem executa comandos.

### Proposto

**Onde fica e como roda.** Projeto uv próprio em `agent/` na raiz do repositório (`agent/pyproject.toml`, `agent/ares_agent/`, `agent/tests/`), separado do `backend/` para que o agente não puxe as dependências do Core. Python 3.14. Dependência de execução: `httpx` (BSD-3-Clause; verifica TLS por padrão e tem tempos-limite). O resto é biblioteca padrão. Comandos:

- `ares-agent enroll --server <url>`: troca o token de enrolamento pela credencial. O token é lido por prompt oculto ou stdin, nunca por argumento (não fica no histórico do shell).
- `ares-agent run`: laço de polling.
- `ares-agent status`: estado local (fila, último envio, último erro), sem segredos.

**Configuração local.** `%LOCALAPPDATA%\ARES\agent\config.toml`: `server_url`, `poll_interval_seconds` (padrão 15; mínimo 5; o servidor limita por agente, 6000 eventos por minuto), `batch_size` (máximo 100), `queue_max_events`, `ca_file` (opcional). Não existe opção que desligue a verificação de certificado.

**Transporte.** `server_url` precisa ser `https://`, exceto `http://` para `localhost`, `127.0.0.1` e `::1` (desenvolvimento, em que o Core roda sem TLS). Respostas do servidor têm tamanho máximo e só os campos conhecidos são lidos. O agente ignora qualquer instrução vinda na resposta: não existe canal de comando.

**Coleta.** Cada ciclo roda `wevtutil qe Security` com filtro XPath por `EventID` e `EventRecordID` maior que o último confirmado, saída em XML, sem shell e com argumentos fixos (nenhum valor de evento vai para a linha de comando). O XML do evento é conteúdo **não confiável** (nomes de usuário e estações vêm de terceiros): é lido com o `xml.etree` da biblioteca padrão (o `expat` recente limita expansão de entidades), com limite de tamanho, e **nunca** é enviado cru.

**Mapeamento e minimização.** Lista fixa de campos por `EventID`; o que não está na lista não sai do host. Nunca se coleta linha de comando, conteúdo de arquivo, senha ou texto livre da mensagem do evento.

| EventID | `event_type` | Campos em `data` (proposta) |
|---|---|---|
| 4624 | `authentication.success` | usuário, domínio, tipo de logon, estação, endereço de origem, processo |
| 4625 | `authentication.failure` | usuário, domínio, tipo de logon, estação, endereço de origem, status e substatus |
| 4648 | `authentication.explicit_credentials` | usuário de origem, usuário-alvo, processo |
| 4672 | `privilege.special_assigned` | usuário, domínio |
| 4720 | `account.created` | conta criada, quem criou |
| 4732 | `group.member_added` | membro, grupo, quem alterou |

Todos com `source.module = endpoint`, `source.instance_id = <agent_id>` e `data_classification = personal` (nomes de usuário e endereços). `severity` fica vazia na 04a: o agente informa fatos, não avalia.

**Identidade do evento.** `event_id` determinístico (UUIDv5 de `host_id + canal + EventRecordID`). Reenvio depois de perda de fila ou de bookmark vira `duplicate` no servidor, sem lógica extra no agente. Ver item 3 em aberto.

**Entrega com garantia "pelo menos uma vez".** O bookmark (maior `EventRecordID` confirmado) só avança depois do 202 com `accepted` ou `duplicate` para o evento. Tratamento por resultado:

| Resposta | Ação |
|---|---|
| 202, evento `accepted` ou `duplicate` | Confirma, avança o bookmark. |
| 202, evento `rejected` | Descarta, registra o código estável e conta; **não reenvia** (evita lote envenenado). |
| 429 | Espera `Retry-After`. |
| 408, 5xx, rede | Reenvia com recuo exponencial e jitter, teto de 5 min. |
| 401 | **Para** e informa "credencial inválida ou revogada". Não repete: credencial revogada não volta. |
| 400, 413, 422 | Erro do próprio agente: registra, descarta o lote e segue; nunca repete em laço. |

**Fila local limitada.** SQLite (biblioteca padrão) em `%LOCALAPPDATA%\ARES\agent\queue.db`, limite por número de eventos e por tamanho. Cheia, descarta os **mais antigos** e conta os descartes (`queue_dropped`); o contador sai no `status` e no próximo evento `agent.queue_overflow`. Diretório só do usuário (ACL herdada de `%LOCALAPPDATA%`).

**Credencial no host.** Guardada fora do `config.toml`. Alternativa recomendada: Gerenciador de Credenciais do Windows, pela biblioteca `keyring` (backend nativo). Ver item 4 em aberto.

**Logs do agente.** JSON estruturado, caracteres de controle escapados, sem credencial, sem conteúdo de evento (só contagens, códigos e `request_id`).

**Heartbeat.** O Core hoje só atualiza `last_seen_at` quando chega evento. Agente ocioso parece desconectado. Ver item 2 em aberto.

**Fora da 04a.** Windows Service (04b); inventário, processos, árvore de processos, hashes e monitoramento de diretórios (spec 4.4); Sysmon; Linux; empacotamento em executável; comandos do servidor para o agente (nunca).

### Testes propostos

- **Mapeamento:** XML sintético (nunca log real) por `EventID`; campos fora da lista não saem; XML com entidades e com `\n` em nome de usuário; evento acima de 16 KB de `data`.
- **Entrega:** bookmark só avança após ack; `rejected` não repete; 401 para o laço; 429 respeita `Retry-After`; recuo com jitter; perda da fila reenvia e o servidor devolve `duplicate`.
- **Fila:** cheia descarta o mais antigo e conta; reiniciar o processo mantém a fila.
- **Transporte:** `http://` fora de loopback recusado; certificado inválido recusado; sem opção para desligar a verificação; resposta acima do limite descartada.
- **Segurança:** credencial nunca aparece em log, `status` ou mensagem de erro; token de enrolamento não vai para argumento nem histórico.
- **Integração:** agente contra o Core real (PostgreSQL de teste): enrola, envia lote, evento sai por `GET /events/{id}` com `<script>` como texto, revogação gera 401 e o agente para, termo revogado corta o agente enrolado.
- **Manual (autor, na própria máquina):** falha de logon local deliberada gera 4625 e o evento chega ao Core.

## Em aberto

| # | Item | Alternativas | Risco de adiar |
|---|---|---|---|
| 1 | **Privilégio para ler o Security log.** O Security log exige administrador elevado ou participação no grupo "Event Log Readers"; um processo normal do usuário não lê. Isso conflita com "não exige privilégio elevado" (complemento, item 2) | (a) adicionar o usuário ao grupo `Event Log Readers` (muda configuração do sistema; vale após novo logon); (b) rodar em terminal elevado; (c) 04a só com canal legível sem privilégio (sem valor de segurança) | Sem decisão, a coleta não funciona. **Recomendo (a)**, feito por você; o agente checa o acesso ao iniciar e falha com mensagem clara. Não altero o sistema sem sua confirmação |
| 2 | **Heartbeat do agente** | (a) rota nova `POST /api/v1/agents/heartbeat` (204; só atualiza `last_seen_at`; exige alteração do complemento 3.2); (b) evento `agent.heartbeat` por `POST /events`; (c) nenhum | (b) enche `events` (cerca de 1.440 por dia a cada 60 s); (c) deixa agente ocioso parecendo desconectado. **Recomendo (a)** |
| 3 | **`event_id` determinístico (UUIDv5) × item "event_id squatting" do ADR 0006**, que sugeria exigir UUIDv4 | Manter UUIDv5 (reenvio idempotente sem estado) e aceitar o risco baixo (agente autenticado); ou UUIDv4 persistido na fila | Baixo; o servidor não verifica a versão do UUID hoje. **Recomendo UUIDv5** e registrar a aceitação |
| 4 | **Onde guardar a credencial no host** | `keyring` (Gerenciador de Credenciais; dependência extra, compatibilidade com Python 3.14 a verificar); DPAPI via `ctypes` (sem dependência, mais código nosso); arquivo com ACL só do usuário (mais simples, mais fraco) | Credencial em arquivo legível por malware do mesmo usuário. **Recomendo `keyring`**, depois de testar no 3.14 |
| 5 | **TLS no laboratório** | Core atrás de proxy com certificado de uma CA local (`ca_file`); ou só loopback em HTTP no desenvolvimento | Demonstração fora de loopback exige certificado. Sem decisão, a 04a funciona só em loopback |
| 6 | **Escopo da coleta** | Só Security log na 04a (recomendado); depois processos, arquivos e Sysmon em fase própria | Escopo cresce sem critério |
| 7 | **Privacidade (seção 5 do complemento, em branco)** | O agente coleta dado pessoal (usuário, estação, endereço de origem). Uso só na máquina do próprio autor, com termo registrado, e classificação `personal` | Antes de qualquer uso real, a análise de LGPD precisa ser feita por quem usar. Não preencho a seção 5 sem pedido |
| 8 | **Retenção local** (fila e logs do agente) | Fila: limite por número e tamanho; log do agente com rotação | Crescimento no disco do usuário |
| 9 | **Licenças** (`httpx`, `keyring` e dependências) | Registrar a análise antes da publicação | Mesma pendência do `psycopg` (LGPL) |

## Consequências

- Primeiro cliente real do contrato de eventos: qualquer defeito do envelope, do limite ou da deduplicação aparece aqui.
- Cria um segundo projeto (`agent/`) com ciclo próprio; o CI, quando existir, roda os dois.
- O agente depende de decisão sua sobre privilégio (item 1) antes de ler o Security log; sem ela, só os testes com XML sintético rodam.
- A leitura por `wevtutil` evita dependência nativa (como `pywin32`) e funciona em qualquer Windows 11, ao custo de um processo por ciclo.
- Dado pessoal passa a existir no banco do Core. O Core ainda não tem retenção nem controle de acesso por `data_classification` (itens abertos do ADR 0006).
