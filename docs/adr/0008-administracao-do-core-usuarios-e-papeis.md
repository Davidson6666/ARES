# ADR 0008 — Administração do Core: usuários, papéis e permissões (fase 01c)

| Campo | Valor |
|---|---|
| Status | Proposto |
| Data | 2026-11-28 |
| Revisar até | 2026-12-12 |

## Contexto

- A fase 01 (01a e 01b) está na `main`. Ficaram de fora, por escolha do autor em 27/11/2026, as rotas de administração de usuários e papéis, e de módulos e configuração (CLAUDE.md, seção 11).
- Hoje só o CLI cria usuário (`create-admin`) e só existe o papel concedido por ele. Não há rota para criar usuário, trocar papéis, desativar conta ou ver o catálogo de permissões. As fases com detecção e tela (03, 08) dependem disso.
- Complemento v1.2, seção 3.2, define as rotas: `GET/POST /users`, `PATCH /users/{id}`, `POST /users/{id}/disable`, `PUT /users/{id}/roles`, `GET/POST /roles`, `PUT /roles/{id}/permissions`, `GET /permissions`, `POST /modules/register`, `POST /modules/{id}/heartbeat`, `GET /modules/{id}`, `PATCH /modules/{id}/config`, `GET /config` e `PATCH /config/{key}`.
- Regras já escritas: `Idempotency-Key` em `POST /users`; paginação por cursor (`limit` 50, máximo 200); atribuição em massa proibida (`PATCH /users/{id}` com `roles` → 422); `user_roles` e `role_permissions` com PK composta; remoção de papel gera auditoria; o último administrador ativo não pode perder `roles.manage`; usuário nunca é apagado (`status = disabled`); desativar revoga as sessões (complemento 3.2).
- Já existem: catálogo de 15 permissões e 5 papéis de sistema (migração 0002, ADR 0003), `require_permission`, sessão com CSRF, MFA (ADR 0005), auditoria encadeada (ADR 0004), escopo por `users.tenant_id`.
- Itens em aberto herdados (CLAUDE.md 4.3): `DELETE /auth/mfa` aceita "próprio usuário ou `users.write`", mas a rota não tem `{id}`; falta o comando `revoke-mfa`.

## Decisão

### Confirmado (complemento e CLAUDE.md)

- As rotas, permissões e códigos de sucesso da seção 3.2 do complemento, na parte de usuários, papéis e permissões.
- Regras transversais acima (cursor, `Idempotency-Key`, campos explícitos, auditoria, último administrador).

### Proposto

**1. Escopo da 01c: só usuários, papéis e permissões.** Módulos e configuração (`/modules*`, `/config*`) ficam para quando existir o primeiro engine (fase 02 ou 03): hoje nada registra módulo nem lê configuração, e desenhar o contrato sem consumidor seria chute. O heartbeat de **agente** já existe (ADR 0007).

**2. Criação de usuário sem senha na rota.** `POST /users` (`users.write`, `Idempotency-Key`) recebe e-mail e nome e cria a conta **sem senha utilizável**. A resposta devolve **uma vez** um token de configuração inicial (uso único, 24 h, só o hash no banco), pelo mesmo mecanismo de `recovery_tokens`: o novo usuário define a senha em `POST /auth/recovery/confirm` e é obrigado a cadastrar o TOTP no primeiro login. O administrador nunca conhece a senha. Não há envio de e-mail (não existe SMTP): o administrador entrega o token por canal próprio. O e-mail é normalizado em minúsculas e único.

**3. Papéis.**
- Os 5 papéis de sistema são **imutáveis** (nome e permissões). `POST /roles` cria papel personalizado; `PUT /roles/{id}/permissions` só altera papel personalizado.
- **Sem escalada de privilégio:** quem concede papel ou permissão só concede o que já tem (um `roles.manage` sem `evidence.export` não monta papel com `evidence.export`).
- `PUT /users/{id}/roles` substitui o conjunto de papéis (`roles.manage`); cada papel removido ou adicionado gera uma linha de auditoria.
- **Último administrador ativo:** nenhuma operação (trocar papéis, mudar permissões do papel, desativar) pode deixar o sistema sem pelo menos um usuário ativo com `roles.manage`. A checagem e a mudança ocorrem na mesma transação, com trava, para duas requisições simultâneas não esvaziarem o grupo.
- Ninguém altera os próprios papéis nem desativa a si mesmo pela API.

**4. Desativar usuário.** `POST /users/{id}/disable` (`users.write`): `status = disabled`, revoga todas as sessões na mesma transação, invalida tokens de recuperação e de configuração pendentes, audita. Reativar não está na spec: fica fora (item em aberto).

**5. `PATCH /users/{id}`** altera só `display_name` (e `tenant_id`, só por `users.write` sem escopo de tenant). Qualquer outro campo (`roles`, `status`, `email`, `password_hash`) → 422. Troca de e-mail não entra na 01c (exige reverificação).

**6. Leitura e escopo.** `GET /users` e `GET /roles` com cursor opaco e assinado; usuário com `tenant_id` só vê usuários do próprio escopo (fora dele, 404, como em eventos). A resposta nunca traz hash de senha, segredo de MFA nem token. `GET /permissions` (`roles.manage`) devolve o catálogo.

**7. MFA e sessões de outro usuário (fecha o item do CLAUDE.md 4.3).** Nova rota `POST /users/{id}/mfa/reset` (`users.write` + reautenticação do administrador): revoga o fator ativo e todas as sessões do alvo, audita, e o alvo recadastra o TOTP no próximo login. `DELETE /auth/mfa` continua só do próprio usuário (o texto do complemento é corrigido). `GET /auth/sessions` e `DELETE /auth/sessions/{id}` passam a aceitar `users.write` para sessões de outro usuário, como o complemento diz. Comando `revoke-mfa` do CLI: ver "Em aberto".

**8. Privilégios do banco.** `ares_app` ganha `INSERT` em `users`, `roles`, `user_roles`, `role_permissions`, e `DELETE` **só** em `user_roles` e `role_permissions` (a remoção de vínculo precisa existir); nunca `DELETE` em `users`. `UPDATE` em `users` por coluna (acrescenta `display_name`, `status`, `tenant_id`). Papel de sistema protegido também por `CHECK` e gatilho no banco, não só no app.

### Testes propostos (CLAUDE.md 9.2)

- Atribuição em massa: `PATCH /users/{id}` com `roles` → 422 (alta).
- IDOR: usuário com tenant A não lê nem altera usuário do tenant B (404) (alta).
- Último administrador: três caminhos (trocar papéis, mudar permissões, desativar) e duas requisições simultâneas; o grupo nunca esvazia.
- Sem escalada: conceder permissão que não tem → 403.
- Desativar: sessões morrem na hora; tokens pendentes morrem; auditoria com uma linha.
- Papel de sistema imutável pela API e pelo banco.
- Token de configuração: uso único, expira, nunca em log nem em resposta repetida (mesma `Idempotency-Key` não devolve o token).
- Reset de MFA exige reautenticação, revoga sessões do alvo, não vale para si mesmo.
- Resposta sem hash, segredo ou token em nenhuma rota.
- Mutação: remover a trava do último administrador e a checagem de escalada faz os testes falharem.

## Em aberto

| # | Item | Alternativas | Risco de adiar |
|---|---|---|---|
| 1 | **Reativar usuário** (não está na spec) | Rota `POST /users/{id}/enable`; ou só por CLI | Conta desativada por engano só volta por banco/CLI |
| 2 | **Comando `revoke-mfa` no CLI** (pendente desde a fase 01a) | Implementar junto, para o caso de o único administrador perder o TOTP e os códigos de recuperação | Sem ele, o administrador trancado fora depende de `issue-recovery` e de códigos |
| 3 | **Troca de e-mail e de senha de outro usuário** | Fora da 01c; senha só por recuperação | Baixo |
| 4 | **Módulos e configuração** (`/modules*`, `/config*`) | 01d, quando existir o primeiro engine | Rotas da spec sem implementação até lá |
| 5 | **Validade do token de configuração inicial** | 24 h (proposta), como o de enrolamento de agente; ou 15 min como a recuperação | Token de senha inicial vivo por mais tempo |
| 6 | **Papéis personalizados: limite de quantidade e nome** | Sem limite; ou teto | Baixo |

## Consequências

- O Core passa a ser administrável pela API: pré-requisito para a tela (fase 08) e para o controle de acesso das fases com detecção.
- A regra "sem escalada" e a do último administrador viram invariantes testadas, inclusive sob concorrência.
- `ares_app` ganha `INSERT` e dois `DELETE` restritos: a matriz de privilégios (e o teste de migração) cresce e precisa de revisão de segurança.
- Sem SMTP, o onboarding depende de o administrador entregar o token por outro canal.
