---
name: model-routing
description: Separa o trabalho por custo de modelo. Planejamento, decisao, arquitetura e revisao de seguranca vao para Opus. Trabalho repetitivo e mecanico (buscar, listar, formatar, renomear, checar links, resumir saida de comando) vai para Haiku via subagente. Use ao iniciar qualquer tarefa com mais de um passo.
---

# Roteamento de modelo por custo

## Regra

- **Opus** pensa: planeja, decide, desenha, revisa criticamente e resolve ambiguidade.
- **Haiku** executa o mecânico: tarefas com saída verificável e sem julgamento.
- A sessão principal coordena: divide a tarefa, delega, confere o resultado do Haiku e responde ao autor.

## Como delegar

Use a ferramenta Agent com `model`:

- Planejamento e decisão: `model: "opus"`.
- Trabalho mecânico: `model: "haiku"`.

Se a sessão atual já for Opus, planeje na própria sessão e não gaste um subagente a mais.

Se a sessão atual for Haiku, planeje com subagente `model: "opus"`. Não tente planejar na sessão.

## O que vai para Haiku

- Buscar arquivos ou símbolos e listar ocorrências (`Grep`, `Glob`).
- Formatar Markdown, ajustar tabelas, corrigir numeração e índice.
- Renomear ou mover arquivos sem mudar conteúdo.
- Checar links, caminhos e referências cruzadas entre `CLAUDE.md` e `docs/`.
- Rodar comando conhecido e resumir a saída (testes, lint, `git status`).
- Gerar boilerplate já especificado linha a linha pelo Opus.
- Conferir checklist do histórico de versões.

## O que NÃO vai para Haiku

- Decisão de arquitetura, modelo de dados, API ou segurança.
- Interpretar requisito ambíguo da especificação.
- Escolher entre alternativas ou avaliar risco.
- Revisão de segurança final (usar `security-reviewer`, com Opus).
- Qualquer tarefa que toque autenticação, sessão, MFA, autorização ou segredo.

## Protocolo

1. Opus (ou a sessão, se já for Opus) escreve o plano: passos numerados, arquivos, critério de aceite.
2. Para cada passo, classifique: pensamento ou mecânico.
3. Mecânico vai para Haiku, com prompt fechado: arquivo, ação exata e formato de saída.
4. Haiku não recebe permissão para decidir. Se encontrar algo fora do prompt, devolve o achado e para.
5. A sessão principal confere a saída do Haiku (`Grep`, leitura do diff) antes de aceitar.
6. Divergência entre plano e resultado volta para o Opus. Não corrija em silêncio.

## Restrições do projeto

- `CLAUDE.md` seção 3: Claude implementa a pedido do autor. Código de funcionalidade fica com a sessão principal (Opus) ou com o plano aprovado; Haiku só faz trabalho mecânico listado acima.
- Não dê a Haiku nenhum segredo, valor de `.env` ou credencial.
- Subagente de Haiku não instala skill, plugin ou MCP. Essa decisão é do autor.
- Nunca marque algo como implementado com base só na saída do Haiku. Use teste ou leitura do código.

## Saída para o autor

Ao final, informe em uma linha por etapa: modelo usado, o que foi feito e se a verificação passou.
