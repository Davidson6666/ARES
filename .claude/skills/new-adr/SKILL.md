---
name: new-adr
description: Cria um novo ADR em docs/adr/ para decisao arquitetural dificil de reverter. Use quando o autor pedir um ADR explicitamente.
disable-model-invocation: true
---

Cria um ADR em `docs/adr/` seguindo `CLAUDE.md` (seções 3 e 4.3).

Argumento: título curto da decisão. Se faltar, pergunte.

Passos:

1. Liste `docs/adr/` e escolha o próximo número sequencial de 4 dígitos (`0001`, `0002`...).
2. Crie `docs/adr/NNNN-titulo-em-kebab-case.md` com o modelo abaixo.
3. Preencha só o que está confirmado no complemento ou com o autor. O restante vai em "Em aberto".
4. Não marque nada como implementado.

Modelo:

```markdown
# ADR NNNN — Título

| Campo | Valor |
|---|---|
| Status | Proposto |
| Data | AAAA-MM-DD |
| Revisar até | AAAA-MM-DD |

## Contexto

## Decisão

## Confirmado

## Proposto

## Em aberto

| Item | Alternativas | Risco de adiar |
|---|---|---|

## Consequências
```

Ao final, diga o caminho do arquivo criado e quais seções ficaram em aberto.
