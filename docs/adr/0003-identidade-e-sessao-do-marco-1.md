# ADR 0003 — Identidade e sessão do marco 1

| Campo | Valor |
|---|---|
| Status | Aceito (autor, 26/11/2026) |
| Data | 2026-11-26 |
| Revisar até | 2026-12-10 |

## Contexto

- O item 4 da seção 21.13 da v1.1 pede identidade, login, sessão e autorização mínima.
- O complemento já fixou: sessão por cookie `Secure`, `HttpOnly`, `SameSite=Strict`, com CSRF em mutações, e nada de token no `localStorage` (seção 1, itens 4 e 7). Também fixou: bootstrap do administrador por CLI (3.3), resposta igual para conta existente e inexistente, e IP nunca persistido na sessão (2.1).
- A seção 21.6 da v1.1 pede definir: expiração da sessão, política de senha, parâmetros do Argon2id, proteção contra força bruta e enumeração, e matriz papel-permissão.
- O `slowapi` não declara Python 3.14 (ADR 0002, em aberto).

## Decisão

### Confirmado pelo autor em 26/11/2026

| Item | Decisão |
|---|---|
| Duração da sessão | 30 min de inatividade e 12 h no máximo. |
| Rate limit do login | Por IP, em memória (janela de 60 s, 10 tentativas por padrão). Por conta, contador de falhas no banco: depois de 5 falhas, bloqueio progressivo de 60 s a 15 min. |
| Política de senha | De 12 a 128 caracteres, sem regra de composição (NIST SP 800-63B). Não pode ser igual ao e-mail. |
| MFA e recuperação | Ficam fora do item 4. Entram num passo seguinte, ainda na fase 01a. |

### Proposto (decisões técnicas deste ADR)

| Item | Decisão | Motivo |
|---|---|---|
| Cookie | Nome `__Host-ares_session` com `Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/`, sem `Domain` e `Max-Age` de 12 h. | O prefixo `__Host-` faz o navegador recusar o cookie se algum desses atributos faltar. |
| Token de sessão | 32 bytes de `secrets.token_urlsafe`. No banco fica só o SHA-256. | Quem vazar o banco não consegue usar as sessões. |
| CSRF | O token é `SHA-256("ares-csrf:" + token de sessão)`, enviado no cabeçalho `X-CSRF-Token` e comparado em tempo constante. É devolvido no login e no `GET /me`. | Não precisa ser gravado, é imprevisível sem o cookie, e o cookie não pode ser obtido a partir dele. O cliente guarda em memória, nunca no `localStorage`. |
| Fixação de sessão | Todo login revoga a sessão anterior daquele navegador e emite um identificador novo. | Teste de aceitação da seção 9.2. |
| Enumeração | Conta inexistente, desativada ou bloqueada recebe o mesmo 401 `invalid_credentials` e gasta o mesmo tempo, com uma verificação Argon2 sobre um hash fictício. | Complemento 3.3 e 4.1. |
| Argon2id | `t=10`, `m=64 MiB`, `p=4`, cerca de 125 ms por verificação nesta máquina. O hash é refeito no login quando os parâmetros mudam. | Custo alto sem passar de 64 MiB por login simultâneo. |
| Login | Exige `Content-Type: application/json` (outro tipo dá 400) e aceita só os campos `email` e `password` (campo extra dá 422). | Formulário entre sites não envia JSON sem preflight. Proteção contra atribuição em massa. |
| Papéis de sistema | `super_admin`, `security_admin`, `security_analyst`, `auditor`, `viewer`, criados pela migração 0002. A matriz está em `backend/migrations/versions/0002_identity.py`. | v1.1, seção 14.5. A matriz exata é proposta e precisa da revisão do autor. |
| Privilégios do `ares_app` | `users` e `sessions`: SELECT, INSERT, UPDATE, **sem DELETE**. `user_roles`: SELECT, INSERT. Catálogo (`roles`, `permissions`, `role_permissions`): só SELECT. | Usuário nunca é apagado e sessão é revogada. Mudanças no catálogo entram com as rotas de administração. |
| Rota protegida mínima | `GET /api/v1/permissions`, que exige `roles.manage`, com paginação por cursor. | Demonstra a autorização no backend exigida pelo critério do marco 1. |

## Em aberto

| Item | Alternativas | Risco de adiar |
|---|---|---|
| Rate limit com vários workers | Contador em PostgreSQL ou Redis | Hoje cada processo conta à parte. Com N workers, o limite efetivo por IP é N vezes maior. Revisar antes de rodar com mais de um worker. |
| IP atrás de proxy | Ler `X-Forwarded-For` só de proxy confiável | Sem proxy, `request.client.host` está correto. Com proxy, todos os clientes compartilham o mesmo limite. Revisar ao definir a implantação. |
| Bloqueio por conta como DoS | Manter, exigir CAPTCHA ou desbloquear por e-mail | Um atacante pode bloquear a conta de alguém por até 15 min. É o custo da proteção contra força bruta. |
| Matriz papel-permissão | Revisar papel a papel | A spec só descreve capacidades gerais. |
| Último administrador não pode perder `roles.manage` | Implementar junto com `PUT /users/{id}/roles` | Ainda não existe rota que altere papéis. |
| Auditoria de login, logout e bootstrap | Item 5 da 21.13 | O critério do marco 1 exige registrar ações sensíveis. |
| Limpeza de sessões expiradas | Tarefa periódica rodando como `ares_owner` | A tabela `sessions` cresce. |

## Revisão de 26/11/2026 (revisões de segurança e de conformidade)

| Achado | Severidade | Mudança |
|---|---|---|
| Corrida no contador de falhas: tentativas simultâneas perdiam incrementos, e o bloqueio podia ser contornado | Alta | O login trava a linha do usuário (`SELECT ... FOR UPDATE`) até o fim. Um teste com 8 tentativas simultâneas exige que as 8 sejam contadas; sem a trava, só 4 eram. |
| Memória do Argon2 sem teto (40 threads × 64 MiB) | Média | No máximo 4 operações Argon2 simultâneas (256 MiB). Se a espera passar de 5 s, a resposta é 503 `busy` com `Retry-After`. |
| Limitador sem teto real de memória e com poda O(n) | Média | LRU com descarte O(1) e teto de 100 mil chaves. IPv6 agrupado por /64. |
| Hash fictício gerado na primeira chamada | Baixa | Gerado na inicialização. |
| CSRF com caractere fora de ASCII causava 500 | Baixa | A comparação passou a ser em bytes; agora responde 403. |
| Corrida no bootstrap | Baixa | O CLI usa `pg_advisory_xact_lock`. |
| `ares_app` com INSERT em `users` e `user_roles` sem rota que precise disso | Baixa | INSERT removido nas duas tabelas. O CLI passa a usar o `ares_owner` (`ARES_MIGRATION_DATABASE_URL`). |
| Banco fora do ar respondia 500 | Divergência (3.4) | Agora responde 503 `dependency_unavailable`. |
| Cursor longo demais respondia 422 | Divergência (3.4) | Agora responde 400 `invalid_cursor`. |
| E-mail fora de ASCII | Consistência | O CLI aceita só ASCII, porque o `lower()` do Python e o do PostgreSQL podem divergir. |

### Registrado

- **Cursor opaco** significa opaco por contrato: o cliente não deve interpretá-lo. Ele não é cifrado; contém o último nome da página em base64url.
- **Permissão** é a coluna `name` (`recurso.acao`), que substitui o par `resource, action` da seção 16 da v1.1.

### Em aberto (adicionado)

| Item | Alternativas | Risco de adiar |
|---|---|---|
| `limit` fora da faixa responde 422 | Manter 422 (falha de esquema) ou 400 ("parâmetro incompatível", v1.1, seção 14.9) | Baixo. A spec é ambígua. |
| Diferença residual de tempo entre os caminhos de falha | Igualar as escritas ou gravar o contador fora do caminho da resposta | Na faixa de 1 a 5 ms sobre 125 ms. Exige muitas amostras, limitadas por IP. |

## Consequências

- O critério do marco 1 fica coberto nesta parte: autenticar um usuário de teste e aplicar permissões no backend.
- Os testes rodam a API como `ares_app` (`SET ROLE`): se faltar um GRANT, o teste falha.
- O teste `test_app_role_privileges_match_matrix` precisa ser atualizado a cada migração que conceder privilégios.
- O teste `test_models_match_migrations` (`alembic check`) impede que os modelos ORM e as migrações divirjam.
