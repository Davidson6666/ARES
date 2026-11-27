# ADR 0005 — MFA (TOTP) e recuperação de conta

| Campo | Valor |
|---|---|
| Status | Aceito (autor, 27/11/2026) |
| Data | 2026-11-27 |
| Revisar até | 2026-12-11 |

## Contexto

- Item do marco 1 (decisão do autor, 26/11/2026): MFA e recuperação entram na fase 01a, depois do item 4.
- Complemento (2.1, 3.2, 4.1): `MfaFactor` com `secret_ref` apontando para cofre, nunca o segredo em texto; `RecoveryCode` em lotes de 10, com hash Argon2id, regeneração invalida os anteriores; `RecoveryToken` de uso único, expira em 15 min, hash, resposta idêntica para conta existente e inexistente; reuso de código TOTP deve falhar na segunda vez.
- CLAUDE.md (seção 6.1): `mfa_factors` com `status` ∈ {pending, active, revoked} e um fator ativo por tipo. Seção 4.1: reautenticação para desativar MFA.
- Decisões do autor em 27/11/2026:
  - segredo TOTP cifrado com chave do ambiente (AES-GCM), sem cofre externo;
  - token de recuperação entregue pelo CLI no servidor, sem SMTP;
  - MFA obrigatório para papéis administrativos.

## Decisão

### Confirmado pelo autor em 27/11/2026

| Item | Decisão |
|---|---|
| Cifra do segredo TOTP | AES-GCM (biblioteca `cryptography` 50.0.2). Chave em `ARES_MFA_KEY` (32 bytes em base64), fora do Git. |
| Entrega do token de recuperação | `uv run python -m app.cli issue-recovery --email <e-mail>`: imprime o token uma vez, no terminal do servidor. |
| MFA para administrador | `super_admin` e `security_admin` não entram sem TOTP ativo. |

### Proposto

| Item | Decisão | Motivo |
|---|---|---|
| Armazenamento do segredo | Tabela `mfa_factors`: `secret_ciphertext` (nonce + texto cifrado + tag) e `secret_ref` = identificador da versão da chave (ex.: `env:v1`). O segredo em claro existe só na resposta do `enroll`. | Permite rotacionar a chave: a versão fica registrada por fator. |
| Ativação | `enroll` cria fator `pending`. `confirm` com um código válido torna-o `active` e revoga qualquer fator ativo anterior do mesmo tipo. | Um fator ativo por tipo (CLAUDE.md 6.1). |
| Reuso de código | Coluna `last_used_step` (contador de 30 s). Código com step ≤ último aceito é rejeitado. Janela de tolerância: ±1 step. | Teste de aceitação 9.2: mesmo código duas vezes, a segunda falha. |
| Login com MFA | Senha correta com fator ativo não cria sessão. Cria um desafio (`mfa_challenges`: hash do token, expira em 5 min, uso único) e um cookie `__Host-ares_mfa` `HttpOnly`. `POST /auth/mfa/verify` troca o desafio por sessão. | Sessão só existe depois do segundo fator. |
| Administrador sem fator ativo | O login devolve um desafio com `enroll_required`. Nesse estado, a única ação permitida é `enroll` + `confirm`, e o `confirm` completa o login. | Administrador não fica sem segundo fator, e também não consegue operar. |
| Desativar MFA | `DELETE /auth/mfa` exige senha e código TOTP válido. Para papéis administrativos, é recusado. | Reautenticação (CLAUDE.md 4.1). Não permite que um administrador desligue o próprio segundo fator. |
| Códigos de recuperação | 10 códigos de 10 caracteres por lote, `RecoveryCode` com hash Argon2id. Gerar novo lote invalida o anterior. Exige sessão com MFA e senha. | Complemento 2.1. |
| Token de recuperação | 32 bytes, SHA-256 no banco, 15 min, uso único. Criado pelo CLI. Ao usar: troca a senha, revoga todas as sessões e **não** desativa o MFA. | Recuperar a senha não pode servir de atalho para contornar o segundo fator. |
| Resposta de recuperação | `POST /auth/recovery/confirm` responde 401 `invalid_recovery` igual para token inexistente, expirado, usado ou de conta desativada. Rate limit por IP. | Complemento 4.1: sem enumeração. |
| Auditoria | `mfa.enroll`, `mfa.confirm`, `mfa.disable`, `mfa.verify` (sucesso e falha), `mfa.recovery_codes_issued`, `auth.recovery_issued` (CLI, ator system), `auth.recovery_used`. | Ações sensíveis do marco 1. |
| Rotas | `POST /api/v1/auth/mfa/enroll` (201), `POST /api/v1/auth/mfa/confirm` (200), `POST /api/v1/auth/mfa/verify` (200), `DELETE /api/v1/auth/mfa` (204), `POST /api/v1/auth/recovery-codes` (201), `POST /api/v1/auth/recovery/confirm` (200). | Complemento 3.2. (`verify` consta na v1.1, seção 15, e não no complemento 3.2; a rota `POST /auth/recovery` da v1.1 foi substituída pelo comando `issue-recovery` do CLI.) |
| Biblioteca TOTP | `pyotp` 2.12.1. | Já verificada no PyPI (ENVIRONMENT.md, seção 4). |

## Em aberto

| Item | Alternativas | Risco de adiar |
|---|---|---|
| Rotação da chave `ARES_MFA_KEY` | Recifrar todos os fatores com a nova versão (script do ares_owner) | Sem rotação, comprometer a chave expõe todos os segredos TOTP. |
| Chave perdida | Não recuperável: os fatores precisam ser refeitos | Backup da chave fica fora do Git, junto com a política de backup (item 21.5, em aberto). |
| Fator alternativo ao TOTP | Nenhum por enquanto (decisão de escopo) | Usuário sem app autenticador fica sem MFA. |
| Recuperação sem acesso ao servidor | SMTP, quando houver operação real | Só o administrador consegue recuperar contas hoje. |
| Revisão da lista de papéis administrativos | Incluir `auditor` ou não | Baixo. |

## Revisão de 27/11/2026 (revisões de segurança e de conformidade)

| Achado | Severidade | Mudança |
|---|---|---|
| Falha de MFA não contava contra a conta: com a senha, dava para palpitar 50 códigos por minuto por IP (cerca de 20% de chance por dia contra um TOTP de 6 dígitos) | Alta | Falha no `/mfa/verify` conta em `users.failed_login_count` e aplica o mesmo bloqueio progressivo do login. Senha correta **não** zera o contador; só o login completo zera. Conta bloqueada não passa pelo `/verify`. Limite por IP também no `/verify`. Os testes de mutação confirmam: sem a contagem, os dois testes de bloqueio falham. |
| `enroll` por sessão roubada deixava o atacante virar dono do segundo fator | Média | `enroll` por sessão exige a senha atual. No desafio (administrador sem TOTP), a senha acabou de ser conferida no login. |
| Falha de reautenticação por senha em `enroll`, `disable` e `recovery-codes` não tinha limite | Baixa | Contam na mesma conta e entram no bloqueio. |
| 422 de senha fraca só ocorria com token válido (oráculo) | Baixa | O tamanho da senha é conferido antes de olhar o token. A regra "senha igual ao e-mail" continua depois, porque exige o usuário. |
| Falha ao decifrar o segredo virava 500 | Baixa | Vira 503 `mfa_unavailable`, sem detalhe. |
| `Cache-Control: no-store` faltava em `/verify` e no login | Baixa | Toda resposta sob `/api/v1/auth/` sai com `no-store`. |
| Corrida entre recuperação e `/verify` em andamento: a sessão nova sobrevivia | Baixa | `/verify` e `use_recovery_token` travam a linha do usuário. |
| Cada tentativa inválida de recuperação gravava uma linha permanente de auditoria | Baixa | Passou a ser só log, como `login.rate_limited` (ADR 0004). |
| `secret` aparecia no `repr` de `Enrollment` | Baixa | `repr=False`. |
| Dois `enroll` concorrentes deixavam dois pendentes e quebravam o `confirm` | Baixa | O `confirm` usa o pendente mais novo. |
| `confirm` não revogava o fator ativo anterior (texto deste ADR) | Divergência | Revoga. Conflito concorrente vira 409 `mfa_already_enrolled`. |
| O revisor de segurança disse que o `.env.example` tinha uma chave válida | Não procede | Conferido: o valor tem 24 caracteres e não decodifica como chave (é um placeholder). A chave real fica só no `.env`. |

### Decisões e exceções registradas

- **CSRF no caminho do desafio:** o `enroll` e o `confirm` feitos com o cookie do desafio (administrador sem TOTP) não exigem `X-CSRF-Token`, ao contrário do caminho por sessão. Justificativa: o cookie é `__Host-`, `SameSite=Strict`, dura 5 minutos e só serve para `enroll` e `confirm`. É uma exceção ao complemento 3.1; fica registrada aqui.
- **`DELETE /auth/mfa` do complemento 3.2** diz "próprio usuário ou `users.write`". A rota não tem `{id}`, então só o próprio usuário é aceito, e papéis administrativos são recusados. Falta decidir se haverá uma rota própria para um administrador desativar o MFA de outro usuário.
- **`secret_ref`:** o complemento 2.1 diz que aponta para um cofre. Aqui ele guarda a versão da chave (`env:v1`) e o segredo cifrado fica em `secret_ciphertext`. O complemento 2.1 e o CLAUDE.md 6.1 precisam ser alinhados.

### Em aberto (adicionado)

| Item | Alternativas | Risco de adiar |
|---|---|---|
| Comando de CLI para revogar o fator MFA de uma conta | `revoke-mfa --email`, auditado como `system` | Hoje, quem perde o app autenticador e os códigos de recuperação não tem saída. **Precisa de aprovação do autor.** |
| Cada palpite de código de recuperação com formato válido roda até 10 verificações Argon2 (cerca de 1,25 s) | Busca por HMAC com chave do ambiente e uma única verificação Argon2 | Quem tem a senha pode saturar as 4 vagas de Argon2, mas só consegue 5 palpites antes do bloqueio da conta. |
| Administrador recém-criado cadastra o TOTP só com a senha | O `create-admin` entregar o primeiro TOTP, ou exigir token do CLI | Risco residual até o primeiro login legítimo. |
| Sessões de administrador criadas antes desta mudança não passaram por MFA | Revogar as sessões na migração | Valem até expirar (12 h no máximo). |

## Consequências

- Nenhum segredo TOTP fica em texto no banco nem nos logs.
- Login de administrador passa a ter dois passos. O cliente web precisa de uma tela de desafio, que é trabalho do item 08 (dashboard).
- O CLI ganha dois comandos: `issue-recovery` e `rotate-mfa-key` (este último quando a rotação for implementada).
- A tabela `sessions` não muda: o desafio de MFA fica em tabela própria.
