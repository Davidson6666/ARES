# ADR 0005 — MFA (TOTP) e recuperação de conta

| Campo | Valor |
|---|---|
| Status | Proposto |
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
| Entrega do token de recuperação | `uv run python -m app.cli issue-recovery <e-mail>`: imprime o token uma vez, no terminal do servidor. |
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
| Rotas | `POST /api/v1/auth/mfa/enroll` (201), `POST /api/v1/auth/mfa/confirm` (200), `POST /api/v1/auth/mfa/verify` (200), `DELETE /api/v1/auth/mfa` (204), `POST /api/v1/auth/recovery-codes` (201), `POST /api/v1/auth/recovery/confirm` (200). | Complemento 3.2. |
| Biblioteca TOTP | `pyotp` 2.12.1. | Já verificada no PyPI (ENVIRONMENT.md, seção 4). |

## Em aberto

| Item | Alternativas | Risco de adiar |
|---|---|---|
| Rotação da chave `ARES_MFA_KEY` | Recifrar todos os fatores com a nova versão (script do ares_owner) | Sem rotação, comprometer a chave expõe todos os segredos TOTP. |
| Chave perdida | Não recuperável: os fatores precisam ser refeitos | Backup da chave fica fora do Git, junto com a política de backup (item 21.5, em aberto). |
| Fator alternativo ao TOTP | Nenhum por enquanto (decisão de escopo) | Usuário sem app autenticador fica sem MFA. |
| Recuperação sem acesso ao servidor | SMTP, quando houver operação real | Só o administrador consegue recuperar contas hoje. |
| Revisão da lista de papéis administrativos | Incluir `auditor` ou não | Baixo. |

## Consequências

- Nenhum segredo TOTP fica em texto no banco nem nos logs.
- Login de administrador passa a ter dois passos. O cliente web precisa de uma tela de desafio, que é trabalho do item 08 (dashboard).
- O CLI ganha dois comandos: `issue-recovery` e `rotate-mfa-key` (este último quando a rotação for implementada).
- A tabela `sessions` não muda: o desafio de MFA fica em tabela própria.
