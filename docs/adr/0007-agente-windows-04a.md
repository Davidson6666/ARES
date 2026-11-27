# ADR 0007 — Primeiro agente Windows (fase 04a)

| Campo | Valor |
|---|---|
| Status | Aceito (autor, 27/11/2026) |
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

**Configuração local.** `%LOCALAPPDATA%\ARES\agent\config.toml`: `server_url`, `poll_interval_seconds` (padrão 15; mínimo 5; o servidor limita por agente, 6000 eventos por minuto), `batch_size` (máximo 100), `queue_max_events`, `queue_max_bytes`, `heartbeat_interval_seconds` (padrão 60) e `ca_file` (opcional). Não existe opção que desligue a verificação de certificado.

**Transporte.** `server_url` precisa ser `https://`, exceto `http://` para `localhost`, `127.0.0.1` e `::1` (desenvolvimento, em que o Core roda sem TLS). Respostas do servidor têm tamanho máximo e só os campos conhecidos são lidos. O agente ignora qualquer instrução vinda na resposta: não existe canal de comando.

**Coleta.** Cada ciclo roda `wevtutil qe Security` com filtro XPath por `EventID` e `EventRecordID` maior que o último confirmado, saída em XML, sem shell e com argumentos fixos (nenhum valor de evento vai para a linha de comando). O XML do evento é conteúdo **não confiável** (nomes de usuário e estações vêm de terceiros): é lido com o `xml.etree` da biblioteca padrão (o `expat` recente limita expansão de entidades), com limite de tamanho, e **nunca** é enviado cru.

**Mapeamento e minimização.** Lista fixa de campos por `EventID`; o que não está na lista não sai do host. Nunca se coleta linha de comando, conteúdo de arquivo, senha ou texto livre da mensagem do evento.

| EventID | `event_type` | Campos em `data` (proposta) |
|---|---|---|
| 4624 | `authentication.success` | usuário, domínio, tipo de logon, estação, endereço de origem, processo |
| 4625 | `authentication.failure` | usuário, domínio, tipo de logon, estação, endereço de origem, status e substatus |
| 4648 | `authentication.explicit_credentials` | usuário e domínio de origem, usuário e domínio alvo, processo |
| 4672 | `privilege.special_assigned` | usuário, domínio |
| 4720 | `account.created` | conta criada e seu domínio, quem criou e o domínio dele |
| 4732 | `group.member_added` | membro, grupo, quem alterou e o domínio dele |
| (interno) | `agent.queue_overflow` | quantos eventos a fila local descartou e o total (classificação `internal`, sem dado pessoal) |

Todo evento de `data` leva também `channel`, `windows_event_id` e `record_id` (sem dado pessoal).

Todos com `source.module` igual ao módulo do agente (recebido no enrolamento; o servidor exige que seja o mesmo, `source_mismatch`), `source.instance_id = <agent_id>` e `data_classification = personal` (nomes de usuário e endereços). `severity` fica vazia na 04a: o agente informa fatos, não avalia.

**Identidade do evento.** `event_id` determinístico (UUIDv5 de `agent_id|canal|EventRecordID`). Reenvio depois de perda de fila ou de bookmark vira `duplicate` no servidor, sem lógica extra no agente. Ver item 3 em aberto.

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

### Decisões do autor em 27/11/2026

O autor aceitou o ADR e as recomendações dos itens 1 a 4:

1. **Privilégio:** o usuário entra no grupo `Event Log Readers` (a fazer pelo autor, em PowerShell elevado: comando no README; o assistente não altera o sistema. Em 27/11/2026 o usuário de desenvolvimento ainda não pertence ao grupo). O agente confere o acesso ao iniciar e falha com mensagem clara.
2. **Heartbeat:** rota `POST /api/v1/agents/heartbeat` (204), no complemento 3.2 (v1.2.2).
3. **`event_id`:** UUIDv5 determinístico; o risco de "squatting" do ADR 0006 fica aceito.
4. **Credencial no host:** `keyring`, depois de testar no Python 3.14.

Item 5 (TLS) sem resposta: a 04a começa só em loopback com HTTP, com `ca_file` suportado no agente. CA local para o laboratório fica para quando houver demonstração fora de loopback. Itens 6 a 9 seguem como propostos.

### Ajustes feitos na implementação (27/11/2026)

O desenho acima mudou nos pontos abaixo; o que não aparece aqui ficou como proposto.

- **Leitura do log em UTF-16.** `wevtutil` com saída redirecionada escreve na página de código ANSI (perde caracteres fora dela). Com `/uni:true` sai UTF-16 com BOM; o agente usa isso.
- **Fila como camada durável.** Em vez de "o marcador só avança depois do 202", o marcador (`collected_record_id`) avança **na mesma transação** em que os eventos entram na fila SQLite, e a linha da fila só sai depois do 202. A garantia é a mesma (pelo menos uma vez, sem perda entre a leitura e o envio) e a queda do processo entre as duas etapas não perde nada.
- **Primeira execução lê só eventos novos.** O ponto de partida é o maior `EventRecordID` do log na hora; o histórico não é lido (minimização e volume).
- **`data` ganhou três campos técnicos**, sem dado pessoal: `channel`, `windows_event_id` e `record_id`.
- **Heartbeat** a cada 60 s sem contato (enviar evento também conta como contato), pela rota `POST /api/v1/agents/heartbeat`.
- **Lote recusado por inteiro** (400, 409, 413 ou 422) é descartado, registrado e contado (`batches_dropped_total`); repetir não adiantaria. Estados inesperados (403, 404, 3xx) mantêm os eventos e repetem com recuo: provavelmente a URL está errada. Redirecionamento nunca é seguido (a credencial não vai para outro endereço).
- **Registro que quebra o XML não trava a coleta.** Caracteres que o XML 1.0 não admite (um nome de usuário de logon falho é de quem tenta entrar) viram U+FFFD antes do parse; se ainda assim a página não é XML válido, o agente lê um evento por vez, pula só o registro ruim e o conta (`malformed_total`).
- **`agent.queue_overflow`** entra na fila sem descartar outro evento (senão cada aviso geraria um novo); a fila passa do limite por esse aviso.
- **Coleta de histórico perdido:** se o estado local some, o agente recomeça pelo ponto de partida (eventos novos); quem quiser reler registros antigos define o marcador à mão, e o `event_id` determinístico faz o servidor devolver `duplicate`.
- **`event_id` por agente:** UUIDv5 de `agent_id|Security|EventRecordID`. O `agent_id` vem da própria credencial, então sobrevive à perda do estado local.
- **Credencial só no cofre.** Se o `keyring` falhar, o agente falha fechado (sem plano B em arquivo). Verificado em 27/11/2026: `keyring 25.7.0` (MIT) funciona no Python 3.14.7 com o backend `WinVaultKeyring`.

### Correções da revisão de segurança e de conformidade (27/11/2026)

Revisão de segurança: nenhum achado alto; os médios e a maior parte dos baixos foram corrigidos, cada um com teste (`agent/tests/test_hardening.py`, `test_runner.py`, `test_store.py`).

- **Servidor hostil não derruba o agente.** `Retry-After` com dígitos não ASCII (`str.isdigit` aceita "²") ou enorme, JSON muito aninhado (`RecursionError`), `error_code` que não é texto curto e identificador, e resposta de enrolamento com `module` ou `agent_id` fora do formato ou diferente do `agent_id` embutido na credencial: tudo vira falha transitória (ou recusa de enrolamento), nunca exceção. Qualquer outra exceção num ciclo (disco cheio, banco travado) é registrada só pelo tipo e vira recuo.
- **Sem proxy e sem CA do ambiente** (`trust_env=False`): `HTTP_PROXY` não manda a credencial para um proxy. **Prazo total de 30 s** e **256 KB** por resposta (o prazo por leitura do httpx não limitava um servidor que entrega 1 byte por vez).
- **Log do Windows limpo (EventID 1102).** A numeração de `EventRecordID` recomeça: o agente compara o maior registro do log com o marcador a cada ciclo; se o log encolheu, zera o marcador, sobe a "época" (entra no `event_id`, que não colide com os antigos) e envia `agent.log_reset`. Quem limpa o log para apagar rastro não cega o agente. **A premissa (a numeração recomeça) não foi verificada em máquina real.**
- **Inundação não expulsa o importante.** A fila descarta primeiro os de menor prioridade (4624 e 4625) e, entre iguais, os mais antigos; criação de conta, grupo e privilégio sobrevivem. O atraso da coleta (`collection_lag`) aparece no `status`.
- **Reenrolar (`--force`) esvazia a fila e o marcador** (os eventos antigos levam o `instance_id` do agente anterior e o servidor os recusaria) e avisa quantos descartou. Falha ao guardar a credencial **depois** de o token ser gasto diz ao operador para revogar o agente e gerar novo token.
- **Cofre fixado:** só `WinVaultKeyring`; qualquer outro backend do `keyring` (texto puro, `PYTHON_KEYRING_BACKEND`) é recusado.
- **O aviso `agent.queue_overflow` é atômico** com o zeramento do contador. Registro que quebra o XML não faz o agente repetir a consulta grande a cada passo (um evento por vez no resto do ciclo). Diretório do Windows pela API do sistema, não só por variável de ambiente. `server_url` com aspas ou barra invertida é recusada (quebraria o `config.toml`).
- **Servidor:** `POST /agents/enroll` passou a responder **201** (o complemento 3.2 já dizia; o código respondia 200). O heartbeat só grava `last_seen_at` a cada 30 s.

Itens aceitos como estão: a saída do `wevtutil` é limitada depois de lida (o `/c:` limita a quantidade de eventos, não o tamanho; teto de 32 MB) e o enrolamento não usa `Idempotency-Key` (item 11 em aberto).

**Limitações conhecidas (não são decisões):**

- Sem trava de instância única: dois `run` ao mesmo tempo enviam duplicatas (o servidor deduplica).
- Um registro ilegível **sem** `EventRecordID` extraível trava a coleta (o agente repete com recuo e registra o erro). Não se espera de log do Windows.
- A fila só protege contra crescimento ilimitado dentro do processo do agente; o arquivo `state.db` não é cifrado (dado pessoal em repouso, na pasta do usuário). Cifragem local fica em aberto.
- O agente ainda não foi exercitado contra o Security log real: o usuário de desenvolvimento não pertence ao grupo `Event Log Readers` (o `wevtutil` devolve acesso negado, código 5). Os testes usam XML sintético; o teste manual (falha de logon deliberada gerando 4625) depende do item 1.

## Em aberto

| # | Item | Alternativas | Risco de adiar |
|---|---|---|---|
| 1 | **[decidido 27/11: grupo `Event Log Readers`, a fazer pelo autor]** **Privilégio para ler o Security log.** O Security log exige administrador elevado ou participação no grupo "Event Log Readers"; um processo normal do usuário não lê. Isso conflita com "não exige privilégio elevado" (complemento, item 2) | (a) adicionar o usuário ao grupo `Event Log Readers` (muda configuração do sistema; vale após novo logon); (b) rodar em terminal elevado; (c) 04a só com canal legível sem privilégio (sem valor de segurança) | Sem decisão, a coleta não funciona. **Recomendo (a)**, feito por você; o agente checa o acesso ao iniciar e falha com mensagem clara. Não altero o sistema sem sua confirmação |
| 2 | **[decidido 27/11: rota `POST /agents/heartbeat`, implementada]** **Heartbeat do agente** | (a) rota nova `POST /api/v1/agents/heartbeat` (204; só atualiza `last_seen_at`; exige alteração do complemento 3.2); (b) evento `agent.heartbeat` por `POST /events`; (c) nenhum | (b) enche `events` (cerca de 1.440 por dia a cada 60 s); (c) deixa agente ocioso parecendo desconectado. **Recomendo (a)** |
| 3 | **[decidido 27/11: UUIDv5]** **`event_id` determinístico (UUIDv5) × item "event_id squatting" do ADR 0006**, que sugeria exigir UUIDv4 | Manter UUIDv5 (reenvio idempotente sem estado) e aceitar o risco baixo (agente autenticado); ou UUIDv4 persistido na fila | Baixo; o servidor não verifica a versão do UUID hoje. **Recomendo UUIDv5** e registrar a aceitação |
| 4 | **[decidido 27/11: `keyring`, testado no 3.14]** **Onde guardar a credencial no host** | `keyring` (Gerenciador de Credenciais; dependência extra, compatibilidade com Python 3.14 a verificar); DPAPI via `ctypes` (sem dependência, mais código nosso); arquivo com ACL só do usuário (mais simples, mais fraco) | Credencial em arquivo legível por malware do mesmo usuário. **Recomendo `keyring`**, depois de testar no 3.14 |
| 5 | **TLS no laboratório** | Core atrás de proxy com certificado de uma CA local (`ca_file`); ou só loopback em HTTP no desenvolvimento | Demonstração fora de loopback exige certificado. Sem decisão, a 04a funciona só em loopback |
| 6 | **Escopo da coleta** | Só Security log na 04a (recomendado); depois processos, arquivos e Sysmon em fase própria | Escopo cresce sem critério |
| 7 | **Privacidade (seção 5 do complemento, em branco)** | O agente coleta dado pessoal (usuário, estação, endereço de origem). Uso só na máquina do próprio autor, com termo registrado, e classificação `personal` | Antes de qualquer uso real, a análise de LGPD precisa ser feita por quem usar. Não preencho a seção 5 sem pedido |
| 8 | **Retenção local** (fila e logs do agente) | Fila: limite por número e tamanho; log do agente com rotação | Crescimento no disco do usuário |
| 9 | **Licenças** (`httpx`, `keyring` e dependências) | Registrar a análise antes da publicação | Mesma pendência do `psycopg` (LGPL) |
| 10 | **[decidido 27/11: `member_sid` cortado; domínios mantidos]** **`member_sid` e domínios no evento** (4720, 4732, 4648): o SID identifica a conta de forma mais forte que o nome | Manter (ajuda a correlacionar) ou cortar `member_sid` por minimização | Dado pessoal a mais saindo do host; decisão do autor |
| 11 | **Enrolamento sem `Idempotency-Key`**: uma resposta perdida queima o token de uso único | Aceitar e gerar novo token; ou chave no `enroll` (servidor guarda a credencial cifrada, o que hoje não existe) | Baixo: o operador gera outro token |
| 12 | **Transparência (v1.1, 17.2):** quem lê o dado do agente é quem tem `events.read` (hoje sem escopo por classificação); retenção no Core indefinida | Tabela no README (feita); retenção e acesso por `data_classification` são itens do Core (ADR 0006) | Antes de qualquer uso real |

## Consequências

- Primeiro cliente real do contrato de eventos: qualquer defeito do envelope, do limite ou da deduplicação aparece aqui.
- Cria um segundo projeto (`agent/`) com ciclo próprio; o CI, quando existir, roda os dois.
- O agente depende de decisão sua sobre privilégio (item 1) antes de ler o Security log; sem ela, só os testes com XML sintético rodam.
- A leitura por `wevtutil` evita dependência nativa (como `pywin32`) e funciona em qualquer Windows 11, ao custo de um processo por ciclo.
- Dado pessoal passa a existir no banco do Core. O Core ainda não tem retenção nem controle de acesso por `data_classification` (itens abertos do ADR 0006).
