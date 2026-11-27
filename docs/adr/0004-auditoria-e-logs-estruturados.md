# ADR 0004 — Auditoria e logs estruturados

| Campo | Valor |
|---|---|
| Status | Aceito (autor, 27/11/2026) |
| Data | 2026-11-26 |
| Revisar até | 2026-12-10 |

## Contexto

- O item 5 da seção 21.13 da v1.1 pede auditoria e logs estruturados. O critério do marco 1 exige "registrar ações sensíveis".
- A v1.1, seção 14.8, define o que a auditoria registra: ator, ação, recurso, resultado, timestamp, origem contextual permitida e correlation_id. Os logs são estruturados, com timestamp UTC, nível, serviço e request_id, sem segredos.
- O complemento (2.2) e o CLAUDE.md (6.1, 6.2) pedem `audit_logs` com `prev_hash` e `entry_hash` e FK para `users` com `ON DELETE RESTRICT`. Também registram que o encadeamento detecta alteração, mas não impede quem tem acesso direto ao banco de reescrever a cadeia.
- Teste de aceitação da seção 9.2: um evento com `\n` gera uma única linha de log.

## Decisão

### Confirmado pelo autor em 26/11/2026

| Item | Decisão |
|---|---|
| E-mail de conta desconhecida | Nenhum dado do e-mail digitado é gravado. |
| IP | Não é gravado na auditoria. |

### Proposto

| Item | Decisão | Motivo |
|---|---|---|
| Encadeamento | `entry_hash = SHA-256(prev_hash ‖ JSON canônico)`, com chaves ordenadas, ASCII e timestamp UTC em microssegundos. A primeira entrada usa `prev_hash` de 32 bytes zero. | Alterar ou remover qualquer entrada quebra a verificação a partir dela. |
| Serialização | `pg_advisory_xact_lock` desde a leitura do último hash até o commit. | Sem o lock, gravações simultâneas bifurcam a cadeia. O teste de mutação confirmou: sem o lock, a verificação falha na segunda entrada. |
| Atomicidade | `record()` não faz commit: a ação e a auditoria entram na mesma transação. | Ação sem auditoria não fica gravada. Teste: se a auditoria falha, a sessão do login não é criada. |
| Append-only | O `ares_app` tem só SELECT e INSERT. Um trigger recusa UPDATE, DELETE e TRUNCATE, inclusive para o `ares_owner`. | Defesa em profundidade. O superusuário ainda pode desligar o trigger (ver "Em aberto"). |
| Eventos registrados | `auth.login` (sucesso e falha, com o motivo), `auth.logout`, `auth.csrf_failed`, `authz.denied` (com a permissão que faltou) e `user.bootstrap_admin` (ator `system`). | São as ações sensíveis que existem hoje. |
| Eventos só em log operacional | `login.rate_limited` e `login.busy`. | Sob ataque, não gravar no banco a cada tentativa. |
| Leitura | `GET /api/v1/audit-logs` (exige `audit.read`), da entrada mais recente para a mais antiga, com cursor. Não existe rota de escrita. | v1.1, seção 15. |
| Verificação | `uv run python -m app.cli verify-audit`, como `ares_owner`. O código de saída é 3 se a cadeia estiver quebrada. | Pode rodar periodicamente. |
| Logs | structlog, uma linha JSON por evento (`ensure_ascii`). Chaves com password, token, secret, cookie, authorization ou csrf são redigidas, em qualquer nível de aninhamento. O log de acesso registra método, caminho, status, duração e request_id, sem query nem cabeçalhos. O log de acesso do uvicorn fica desligado, e `httpx`/`httpcore` ficam em WARNING. | v1.1, seção 14.8, e CLAUDE.md, seção 9.1. |

## Em aberto

| Item | Alternativas | Risco de adiar |
|---|---|---|
| Cópia externa da auditoria (CLAUDE.md, 9.3) | Exportar periodicamente os `entry_hash` para um armazenamento fora do servidor, ou assinar checkpoints | Quem tem superusuário consegue desligar o trigger e reescrever a cadeia inteira de forma consistente. A escolha depende de onde o ARES será hospedado. |
| Retenção da auditoria | Seção 5 do complemento (LGPD), em branco | A tabela cresce sem limite. Apagar quebra a cadeia, então será preciso um checkpoint. |
| Contenção do lock global | Particionar a cadeia ou usar fila | Cada ação auditada serializa por alguns milissegundos. Medir antes de mudar. |
| Auditar leitura da própria auditoria | Registrar `audit.read` | Hoje a leitura não é auditada. |

## Revisão de 27/11/2026 (revisões de segurança e de conformidade)

**Correção de texto:** a tabela acima dizia que alterar ou remover *qualquer* entrada quebra a verificação e que o trigger vale "inclusive para o `ares_owner`". As duas afirmações estavam erradas e foram corrigidas a seguir.

| Achado | Severidade | Mudança |
|---|---|---|
| Remover as últimas entradas deixava uma cadeia válida e mais curta | Média | O `verify-audit` imprime a cabeça da cadeia (`<id>:<entry_hash>`) e aceita `--expect-head <id>:<hash>`, que falha se a âncora sumiu ou mudou. A âncora precisa ser guardada **fora do servidor**. Sem âncora, a remoção do fim não é detectada, e o comando avisa isso. |
| O trigger não protege contra o dono da tabela | Média | O `ares_owner` e o superusuário podem desligar o trigger, trocar a função ou apagar a tabela. O trigger evita alteração acidental, nada além disso. Texto, docstring e nome do teste foram corrigidos. |
| Valores de parâmetros e da mensagem do PostgreSQL iam para o log de erro | Média | O engine usa `hide_parameters=True`. Erros de banco são logados só com o tipo e o SQLSTATE, sem a mensagem nem o traceback, porque a mensagem do PostgreSQL pode conter o valor enviado. O login recusa e-mail com caractere de controle (422). |
| Floats e chaves não-string em `details` mudariam o hash na releitura do JSONB | Baixa | `record()` aceita só str, int, bool, None, listas e dicts com chave str. Qualquer outra coisa dá `TypeError`. |
| `resource_id` gravava o caminho concreto, controlado pelo cliente | Baixa | Passa a gravar o template da rota (ex.: `GET /api/v1/users/{id}`). |
| O commit do touch da sessão podia levar junto uma escrita pendente sem auditoria | Baixa | O touch é gravado numa conexão e transação próprias. Um teste mostra que a escrita pendente de quem chamou não é gravada. |
| Lacunas na redação de logs | Baixa | Mais chaves cobertas (`passwd`, `pwd`, `credential`, `otp`, `mfa`, `recovery`, `api_key`, `private_key`). Objeto desconhecido vira `<NomeDoTipo>`, nunca o `repr`. **Limite que continua:** valor sensível sob chave inocente, texto de exceção e mensagens stdlib com `%s` não são redigidos. |
| `alembic downgrade` apagava a trilha sem aviso | Baixa | O downgrade da 0003 é recusado se houver entradas, a menos que `ARES_ALLOW_AUDIT_DROP=1`. |
| Faltava `correlation_id` (v1.1, 14.8 e 16) | Divergência | A coluna foi criada, é incluída no hash e aparece na rota. Hoje fica nula; será preenchida quando houver fluxo com várias requisições. |
| Faltava o campo `service` nos logs (v1.1, 14.8) | Divergência | Todo log inclui `"service": "ares-core"`. |

### Em aberto (adicionado)

| Item | Alternativas | Risco de adiar |
|---|---|---|
| Dono separado para `audit_logs` | Papel NOLOGIN `ares_audit_owner`, do qual o `ares_owner` não seja membro no uso diário | Hoje a credencial de migração, que fica no mesmo host, permite reescrever a cadeia. |
| Volume de negações auditadas | Rate limit por sessão ou agregação (uma entrada por sessão, rota e minuto) | Uma sessão válida em laço gera uma linha permanente por requisição e disputa o lock global. |
| Rotina de âncora externa | Anotar a cabeça periodicamente num lugar fora do servidor | Sem isso, o `--expect-head` não tem o que comparar. |

## Consequências

- O critério do marco 1, "registrar ações sensíveis", fica coberto para as ações que existem hoje. Toda rota nova que fizer algo sensível precisa chamar `audit.record`.
- O login fica um pouco mais lento: um lock e um INSERT a mais por tentativa.
- Teste obrigatório da seção 9.2 coberto: um evento com `\n` gera uma linha de log.
