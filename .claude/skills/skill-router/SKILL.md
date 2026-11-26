---
name: skill-router
description: Escolhe e usa automaticamente a skill, agente ou MCP certo para o momento atual do trabalho no ARES. Use no início de cada tarefa e sempre que a natureza do trabalho mudar (planejar, implementar, depurar, revisar, documentar, verificar, concluir).
---

# Roteador de skills

Antes de responder ou agir, identifique o momento e use a ferramenta indicada. Não espere o autor pedir.

## Tabela de decisão

| Momento | Use | Observação |
|---|---|---|
| Nova funcionalidade ou mudança de comportamento | `superpowers:brainstorming` | Antes de qualquer plano. |
| Plano de fase ou tarefa com vários passos | `superpowers:writing-plans` | Plano segue `model-routing`. |
| Execução de plano já escrito | `superpowers:executing-plans` ou `superpowers:subagent-driven-development` | Mecânico vai para Haiku. |
| Bug, teste falhando, comportamento inesperado | `superpowers:systematic-debugging` | Antes de propor correção. |
| Código novo com teste (Python) | `superpowers:test-driven-development` | Pytest, quando houver código. |
| Revisão de documento Markdown ou prosa | `writing-guidelines` | Para `docs/` e `CLAUDE.md`. |
| Dúvida sobre biblioteca ou API externa | MCP `context7` | Não use memória para versão de API. |
| Teste de interface no navegador | MCP `playwright` | Só quando o frontend existir. |
| Mudança em autenticação, sessão, MFA, autorização, ingestão ou renderização | agente `security-reviewer` (Opus) | Antes de dar a tarefa por pronta. |
| Mudança em rota, modelo de dados ou envelope de evento | agente `spec-compliance-reviewer` | Antes de dar a tarefa por pronta. |
| Decisão arquitetural difícil de reverter | Sugerir `/new-adr` ao autor | Não invocar: a skill é só do autor. |
| Revisão de segurança completa do branch | `/security-review` (built-in) | Só quando o autor pedir. |
| Antes de afirmar que algo está pronto | `superpowers:verification-before-completion` | Obrigatório antes de qualquer "concluído". |
| Fim de branch e decisão de integração | `superpowers:finishing-a-development-branch` | Não faça merge ou push sem pedido. |
| Pedido de nova skill, plugin ou MCP | Não instalar | Só depois de confirmação explícita do autor (`CLAUDE.md` seção 13). |

## Regras

1. Mais de uma linha se aplica? Use a de número menor na ordem de processo: brainstorming → plano → execução → verificação → conclusão. Revisões de segurança e de especificação entram antes da conclusão.
2. Não invoque skill com efeito colateral sem pedido: commit, push, merge, envio de mensagem, deploy, instalação.
3. Não repita skill já aplicada na mesma tarefa, salvo mudança relevante.
4. Se nenhuma linha se aplica, siga sem skill. Não force.
5. Ao usar uma skill ou agente, diga em uma linha qual e por quê.

## Limites

- Os agentes `security-reviewer` e `spec-compliance-reviewer` são somente leitura. Eles apontam problemas; a correção é feita depois.
- MCP `context7` e `playwright` só aparecem após aprovação do autor na sessão.
- Este roteador não instala nada e não altera `.mcp.json` ou `settings.json`.
