ARES

CYBER DEFENSE PLATFORM

Especificação geral do produto e arquitetura detalhada do ARES Core

| Documento | Especificação técnica e arquitetura |
|---|---|
| Versão | 1.0 — baseline inicial |
| Data | 26 de novembro de 2026 |
| Plataforma-alvo | Windows e Linux; painel web |
| Princípio de desenvolvimento | Implementação manual pelo autor; ferramentas gratuitas/open source |

> Nota de status — Este documento descreve o produto pretendido e decisões de projeto propostas. Não afirma que qualquer módulo já esteja implementado. Itens marcados como proposta, hipótese ou questão em aberto deverão ser confirmados durante a engenharia.

# Controle do documento

| Campo | Descrição |
|---|---|
| Objetivo | Consolidar a visão, o escopo, as funcionalidades, a arquitetura e o plano de desenvolvimento do ARES. |
| Público-alvo | Desenvolvedor do projeto, revisores técnicos e futuros colaboradores. |
| Status | Baseline de planejamento v1.0; sujeito a revisão. |
| Abordagem | Desenvolvimento incremental, documentação antes da implementação e validação por testes. |
| Restrições | Orçamento de licenças igual a zero; ambiente principal Windows com 16 GB RAM; uso de laboratórios próprios/autorizados. |

## Como usar este documento

Este arquivo é a referência inicial do projeto. Ele deve ser atualizado quando uma decisão for confirmada, um requisito mudar ou uma funcionalidade for adicionada. Decisões relevantes devem ser registradas em ADRs (Architecture Decision Records), com contexto, alternativas, decisão e consequências.

# Sumário

- 1. Visão e objetivos do ARES

- 2. Escopo e princípios

- 3. Arquitetura geral

- 4. Especificação funcional dos módulos

- 5. Dashboard e experiência do usuário

- 6. Arquitetura de eventos

- 7. Dados e armazenamento

- 8. Segurança transversal

- 9. Tecnologias e ferramentas

- 10. Roadmap e critérios de conclusão

- 11. Qualidade, métricas e testes

- 12. Organização do repositório e documentação

- 13. Laboratório, ética e limites operacionais

- 14. Arquitetura detalhada do ARES Core

- 15. Contratos de API propostos

- 16. Modelo de dados inicial

- 17. Modelo de ameaças do Core

- 18. Plano de testes do Core

- 19. Decisões confirmadas, propostas e questões em aberto

- 20. Glossário e referências

# 1. Visão e objetivos do ARES

ARES (nome de trabalho: Advanced Reconnaissance, Event & Response Security) é uma plataforma modular de cibersegurança defensiva. Seu propósito é centralizar a coleta autorizada de telemetria, a normalização de eventos, a detecção de comportamentos suspeitos, a investigação de incidentes e a apresentação de evidências em uma interface web.

A plataforma deverá ser útil em redes e computadores sob administração legítima do operador. O produto será desenvolvido incrementalmente, com componentes próprios e integrações opcionais com ferramentas open source já consolidadas.

## 1.1 Problema que pretende resolver

Em ambientes pequenos e médios, informações de rede, endpoints, logs, integridade de arquivos e incidentes costumam ficar dispersas em ferramentas diferentes. O ARES pretende fornecer uma visão operacional unificada, sem esconder a origem dos dados nem apresentar conclusões sem evidências.

## 1.2 Objetivos principais

- Coletar telemetria de dispositivos e redes autorizadas.

- Normalizar informações heterogêneas em um modelo comum de eventos.

- Detectar padrões suspeitos com regras explicáveis e correlação temporal.

- Gerenciar alertas e incidentes com contexto e evidências.

- Apoiar investigações forenses preservando a integridade das evidências.

- Proteger dados e comunicações por meio de práticas criptográficas consolidadas.

- Oferecer uma interface web para monitoramento, investigação e administração.

- Manter a própria plataforma observável, auditável e segura.

## 1.3 Não objetivos

- Não é uma ferramenta para invadir sistemas ou redes de terceiros.

- Não pretende substituir integralmente um SIEM/EDR comercial em sua primeira versão.

- Não promete descriptografar tráfego TLS/HTTPS.

- Não executará ações destrutivas ou comandos arbitrários remotamente nos endpoints.

- Não criará algoritmos criptográficos próprios para proteger dados reais.

- Não dependerá de serviços pagos para seu funcionamento básico.

# 2. Escopo e princípios

## 2.1 Princípios de engenharia

- Segurança por padrão: privilégios mínimos, validação de entrada e segredos fora do código.

- Evidência antes de conclusão: alertas devem apontar dados e regras que justificam a classificação.

- Modularidade: responsabilidades e interfaces explícitas entre componentes.

- Incrementalismo: começar com um núcleo funcional e evoluir sem antecipar infraestrutura desnecessária.

- Observabilidade: saúde, logs, métricas e rastreabilidade desde as primeiras versões.

- Testabilidade: cada módulo deve ter testes unitários, de integração e de contrato adequados.

- Portabilidade: considerar Windows e Linux, reconhecendo diferenças entre APIs e fontes de telemetria.

- Custo zero de licenças: priorizar software gratuito e open source; custos de hardware, energia e hospedagem externa não estão incluídos.

## 2.2 Contexto inicial de execução

| Aspecto | Diretriz inicial |
|---|---|
| Estação de desenvolvimento | Windows 10/11, 16 GB RAM. |
| Ambiente Linux | WSL 2 + distribuição Ubuntu, se compatível com a versão do Windows. |
| Contêineres | Docker Desktop com backend WSL 2, opcional conforme necessidade. |
| Execução local | Primeiro alvo: um host; arquitetura preparada para agentes remotos autorizados. |
| Interface | Aplicação web acessível por navegador. |
| Laboratório | Máquinas próprias, VMs e aplicações intencionalmente vulneráveis. |

> Atenção — A versão exata do Windows, CPU, espaço em disco e disponibilidade de virtualização ainda precisam ser verificados antes de fixar limites de recursos e instruções definitivas de instalação.

# 3. Arquitetura geral

A arquitetura será modular. O primeiro estágio recomendado é um monólito modular com interfaces internas bem definidas. Processos separados serão introduzidos quando isolamento, desempenho, ciclo de vida ou permissões justificarem essa separação. Isso evita complexidade operacional prematura.

| Componente lógico | Responsabilidade principal | Interações |
|---|---|---|
| ARES Dashboard | Interface web, visualização e operações do usuário. | API Core e WebSocket. |
| ARES Core | Autenticação, autorização, configuração, catálogo de módulos, orquestração e auditoria. | Todos os módulos. |
| Event Bus | Validação, distribuição, deduplicação e encaminhamento de eventos. | Produtores e consumidores. |
| Network Engine | Telemetria e análise de rede autorizada. | Event Bus, Threat Engine. |
| Threat Engine | Regras, correlação, classificação e alertas. | Event Bus, Core, Analytics. |
| Endpoint Engine | Agentes e telemetria de hosts autorizados. | Core, Event Bus. |
| Forensics Engine | Casos, evidências, análise e linha do tempo. | Core, armazenamento. |
| Crypto Engine | Operações criptográficas e gerenciamento de chaves. | Core e armazenamento seguro. |
| Analytics Engine | Agregações, métricas e relatórios. | Eventos, alertas e incidentes. |
| Data Layer | Persistência relacional, filas/cache e objetos de evidência. | Todos por interfaces autorizadas. |

## 3.1 Diagrama lógico

```
[Agentes / Fontes de rede / Importações]
                 |
                 v
       [Network / Endpoint Engines]
                 |
                 v
             [Event Bus]
                 |
       +---------+----------+
       |                    |
       v                    v
 [Threat Engine]      [Analytics Engine]
       |
       v
 [Alertas / Incidentes]
       |
       v
 [ARES Core / API] <----> [Dashboard]
       |
       +------> [PostgreSQL]
       +------> [Armazenamento de evidências]
       +------> [Redis / fila temporária, se adotado]
```

## 3.2 Limites de confiança

- O navegador é considerado ambiente não confiável; toda autorização é validada no servidor.

- Agentes são autenticados individualmente e não recebem comandos arbitrários.

- Módulos internos validam mensagens recebidas, mesmo quando a origem é outro componente ARES.

- Dados importados e indicadores externos são conteúdo não confiável, nunca instruções executáveis.

- Evidências originais devem ser preservadas; análises ocorrem em cópias ou representações controladas.

# 4. Especificação funcional dos módulos

## 4.1 ARES Core

O Core coordena a plataforma e fornece os serviços transversais. Não deve concentrar lógica especializada de análise de pacotes, detecção comportamental ou forense.

- Autenticação: cadastro administrativo inicial, login, logout, MFA, recuperação e revogação de sessões.

- Autorização: RBAC com permissões por recurso e ação; validação no backend.

- Gestão de módulos: registro, versão, estado, heartbeat, configuração e falhas.

- API: endpoints versionados, validação de esquemas, paginação, filtros e erros padronizados.

- Auditoria: registro de operações administrativas e ações sensíveis.

- Configuração: valores por ambiente, validação de configuração e gestão segura de segredos.

- Observabilidade: logs estruturados, métricas, health checks e correlação por request/event ID.

## 4.2 Network Engine

Responsável por observar e interpretar tráfego em interfaces e redes explicitamente autorizadas. Deve separar captura, decodificação, normalização e análise.

- Descoberta passiva de dispositivos por fontes como ARP, DHCP e tráfego observado.

- Inventário com IP, MAC quando disponível, nome, fabricante estimado por OUI, primeira e última observação.

- Metadados de conexões: origem, destino, portas, protocolo, duração observada e volume.

- Análise de protocolos: TCP, UDP, DNS, HTTP não criptografado, TLS metadata, ICMP e DHCP.

- Topologia baseada em relações observadas, com indicação de confiança e origem dos dados.

- Detecção de anomalias de volume, frequência, destinos incomuns e padrões de consulta DNS.

- Exportação de eventos normalizados para o Event Bus.

> Limitação técnica — A observação de TLS não implica acesso ao conteúdo cifrado. Visibilidade depende do ponto de captura, permissões, configuração de rede e metadados efetivamente disponíveis.

## 4.3 Threat Engine

- Motor de regras declarativas com identificador, versão, descrição, condições, janela temporal e severidade.

- Correlação por dispositivo, usuário, IP, tempo, tipo de evento e indicadores relacionados.

- Classificação separada de severidade e confiança.

- Gestão de IOC: hashes, IPs, domínios e outros indicadores importados, validados e com validade temporal.

- Geração de alertas com regra acionada, evidências, contexto, explicação e recomendação.

- Controle de falsos positivos, supressão documentada e revisão de regras.

- Avaliação de detecção com métricas de precisão, recall, F1 e tempo de detecção em cenários conhecidos.

| Severidade | Interpretação |
|---|---|
| Informativo | Evento relevante sem indicação suficiente de ameaça. |
| Baixo | Comportamento pouco preocupante, mas registrável. |
| Médio | Atividade que merece investigação. |
| Alto | Forte indicação de comportamento malicioso ou impacto relevante. |
| Crítico | Incidente potencialmente grave que exige prioridade. |

Severidade mede impacto/prioridade potencial. Confiança mede a força das evidências. Os dois valores não devem ser confundidos.

## 4.4 Endpoint Engine

- Agente para Windows inicialmente; Linux em etapa posterior.

- Coleta de inventário básico, processos, árvore de processos, usuário, caminho e hash de executáveis quando permitido.

- Monitoramento de diretórios configurados e eventos de criação, alteração e exclusão.

- Coleta de eventos de autenticação do sistema operacional.

- Comunicação autenticada e criptografada com o servidor.

- Fila local limitada e envio posterior quando houver indisponibilidade, com proteção contra crescimento ilimitado.

- Política de privilégios mínimos e transparência sobre os dados coletados.

> Escopo seguro — O agente inicial será de telemetria e monitoramento. Não terá execução remota arbitrária, persistência oculta, evasão ou ações destrutivas.

## 4.5 Forensics Engine

- Análise de tipo real de arquivo por assinatura, metadados e cabeçalhos.

- Hashes criptográficos, incluindo SHA-256, e comparação de integridade.

- Casos de investigação com responsável, status, severidade, eventos e evidências.

- Linha do tempo unificada com origem e precisão temporal dos registros.

- Cadeia de custódia: aquisição, hash, operador, data, acessos, exportações e transformações.

- Análise de cópias e imagens forenses, sem alterar a fonte original.

- Futura recuperação de arquivos em imagens FAT32/NTFS, após validação técnica e testes.

- Exportação de relatório técnico e resumo executivo.

## 4.6 Crypto Engine

- Criptografia autenticada de arquivos com bibliotecas consolidadas.

- Gerenciamento de chaves, rotação, revogação e armazenamento protegido.

- Assinaturas digitais e verificação de integridade.

- TLS para comunicações entre agentes e servidor.

- Registro de operações criptográficas sem registrar segredos ou material de chave.

- Testes de vetores conhecidos, tratamento de erros e revisão das escolhas criptográficas.

> Regra criptográfica — Não inventar cifras, modos, protocolos ou esquemas de derivação de chave para proteger dados reais. A implementação própria será de integração, gestão e fluxo; as primitivas virão de bibliotecas reconhecidas.

## 4.7 Analytics Engine

- Agregações por período, dispositivo, tipo, severidade e origem.

- Tendências de alertas e incidentes.

- Métricas de saúde dos módulos e latência de processamento.

- Detecção estatística de desvios com explicabilidade.

- Relatórios exportáveis em PDF, CSV e JSON.

- Futuro suporte a ClickHouse apenas se o volume justificar.

# 5. Dashboard e experiência do usuário

| Área | Conteúdo e operações |
|---|---|
| Login | Credenciais, MFA, recuperação, mensagens de erro seguras e gestão de sessão. |
| Overview | Dispositivos, eventos, alertas, incidentes, estado dos módulos e atividade recente. |
| Network Monitor | Inventário, conexões, protocolos, DNS, topologia, filtros e histórico. |
| Threat Center | Alertas, severidade, confiança, regras acionadas, evidências, investigação e encerramento. |
| Forensics Center | Casos, evidências, hashes, linha do tempo, anotações e cadeia de custódia. |
| Endpoint Manager | Agentes, última comunicação, versão, SO, saúde e telemetria autorizada. |
| Crypto Vault | Operações criptográficas, arquivos protegidos, chaves e histórico. |
| Administration | Usuários, papéis, permissões, configurações, retenção, backup e auditoria. |

A interface deve exibir claramente a origem e a idade dos dados. Dados desatualizados, agente desconectado ou motor indisponível não podem ser apresentados como estado atual.

## 5.1 Requisitos de usabilidade

- Filtros persistentes e combináveis nas listas de eventos e alertas.

- Paginação no servidor para grandes volumes.

- Detalhes de alerta com explicação e evidências acessíveis.

- Estados vazios, carregamento, erro e dados desatualizados explícitos.

- Ações sensíveis exigem confirmação e registro de auditoria.

- Acessibilidade por teclado, contraste e rótulos adequados.

# 6. Arquitetura de eventos

O Event Bus será a espinha dorsal da comunicação assíncrona. Produtores publicam eventos; consumidores processam os eventos sem depender de chamadas diretas entre todos os módulos.

## 6.1 Envelope padrão proposto

```
{
  "event_id": "UUID",
  "event_type": "authentication.failure",
  "schema_version": 1,
  "occurred_at": "timestamp UTC",
  "observed_at": "timestamp UTC",
  "source": {
    "module": "endpoint",
    "instance_id": "agent-or-engine-id"
  },
  "tenant_id": "optional-scope",
  "device_id": "optional-device-id",
  "correlation_id": "optional-correlation-id",
  "severity": "medium",
  "data": {}
}
```

O envelope definitivo deve definir campos obrigatórios, tamanho máximo, política de dados sensíveis, versão de esquema, validação e regras de compatibilidade.

## 6.2 Garantias e resiliência

- Consumidores idempotentes: processar o mesmo event_id repetido não deve duplicar efeitos.

- Deduplicação com janela e política documentadas.

- Retentativas com backoff limitado para falhas transitórias.

- Fila de mensagens não processadas (dead-letter) com inspeção e reprocessamento controlado.

- Persistência apropriada para eventos que não podem ser perdidos.

- Ordenação apenas onde necessária; não presumir ordem global.

- Backpressure e limites para evitar que um produtor indisponha o sistema.

## 6.3 Fluxo de exemplo

```
Endpoint Agent
  -> valida e normaliza evento
  -> publica no Event Bus
  -> Threat Engine consome
  -> regra/correlação avalia
  -> alerta é persistido
  -> Core disponibiliza pela API
  -> Dashboard atualiza via WebSocket
```

# 7. Dados e armazenamento

PostgreSQL será o banco relacional inicial. Redis poderá ser usado para cache, presença, coordenação ou filas temporárias, desde que não seja tratado como fonte única de dados duráveis.

| Entidade/tabela inicial | Finalidade |
|---|---|
| users | Contas de usuários. |
| roles | Papéis RBAC. |
| permissions | Permissões atômicas. |
| user_roles | Associação usuário-papel. |
| role_permissions | Associação papel-permissão. |
| sessions | Sessões e estado de revogação. |
| mfa_factors | Fatores MFA, com segredos protegidos. |
| devices | Inventário de dispositivos. |
| agents | Identidade, versão e estado de agentes. |
| events | Eventos normalizados ou referência para armazenamento especializado. |
| alerts | Alertas gerados por regras. |
| incidents | Casos operacionais de incidente. |
| detection_rules | Regras versionadas. |
| evidence | Metadados e localização de evidências. |
| investigations | Casos forenses. |
| audit_logs | Trilha de auditoria. |
| module_status | Estado e heartbeat dos módulos. |
| configurations | Configurações não secretas e versionadas. |

## 7.1 Retenção e volume

- Definir retenção por classe de dado e necessidade operacional.

- Indexar campos consultados frequentemente; evitar indexação indiscriminada.

- Considerar particionamento temporal para tabelas de eventos quando houver volume comprovado.

- Separar metadados de evidência do conteúdo binário dos arquivos.

- Planejar backup, restauração e teste periódico de recuperação.

- Minimizar dados pessoais e restringir acesso conforme finalidade.

# 8. Segurança transversal

| Domínio | Controles esperados |
|---|---|
| Identidade | Argon2id para senha; MFA; sessões revogáveis; proteção contra brute force. |
| Autorização | RBAC no servidor; menor privilégio; autorização por recurso/ação. |
| API | Validação de esquema; limites; CORS restrito; erros sem stack trace; proteção contra abuso. |
| Transporte | TLS; autenticação mútua ou credenciais de agente; validação de certificado. |
| Segredos | Nunca versionar; injetar por ambiente/secret store; rotação e acesso restrito. |
| Dados | Criptografia quando necessária; backup protegido; retenção e descarte. |
| Auditoria | Ações sensíveis registradas; proteção contra alteração indevida; acesso restrito. |
| Supply chain | Dependências fixadas e verificadas; atualização controlada; análise de vulnerabilidades. |
| Operação | Privilégios mínimos; isolamento; monitoramento; resposta a falhas. |

## 8.1 Resposta a incidentes da própria plataforma

O ARES deverá registrar falhas de autenticação, mudanças administrativas, alteração de configuração crítica, indisponibilidade de módulo e falhas de integridade. O sistema não deverá ocultar incidentes nem impedir o administrador legítimo de recuperar o controle.

# 9. Tecnologias e ferramentas

| Tecnologia | Uso proposto | Observações |
|---|---|---|
| Python | Backend, integração, automação e análise. | Ecossistema amplo; versão será fixada no setup. |
| FastAPI | API HTTP. | Open source; documentação automática. |
| Rust | Componentes de baixo nível e alto desempenho. | Introduzir apenas quando houver caso de uso. |
| React + TypeScript | Dashboard web. | Aplicação independente consumindo API. |
| PostgreSQL | Persistência relacional. | Banco principal inicial. |
| Redis | Cache/coordenação/fila temporária. | Opcional; não usar como armazenamento durável sem desenho explícito. |
| Docker | Ambientes de desenvolvimento e serviços. | Não obrigatório para cada componente. |
| Pytest | Testes Python. | Unitários e integração. |
| Vitest / Playwright | Testes frontend e ponta a ponta. | Conforme stack final. |
| Git | Versionamento. | Commits pequenos e rastreáveis. |
| Suricata / Zeek | Referência e possível integração de telemetria de rede. | Não substituem os componentes próprios do ARES. |
| Wireshark | Análise e depuração de tráfego de laboratório. | Ferramenta de apoio. |
| Wazuh | Referência de arquitetura e monitoramento de endpoints. | Integração opcional futura. |

> Decisão pendente — A versão exata de Python, Rust, Node.js, PostgreSQL, Redis e Docker será fixada em um arquivo de versões quando a instalação real for preparada. A compatibilidade deverá ser conferida na documentação oficial no momento da instalação.

# 10. Roadmap e critérios de conclusão

| Fase | Escopo | Estimativa inicial |
|---|---|---|
| 01 — Fundação | Repositório, Core, configuração, banco, autenticação inicial, eventos e auditoria. | 3–4 semanas |
| 02 — Network | Coleta autorizada, dispositivos, protocolos, conexões e normalização. | 4–6 semanas |
| 03 — Threat | Regras, correlação, IOC, alertas e incidentes. | 4–6 semanas |
| 04 — Endpoint | Agente Windows, processos, arquivos, autenticação e comunicação segura. | 4–6 semanas |
| 05 — Forensics | Análise, hashes, casos, evidências, timeline e cadeia de custódia. | 4–6 semanas |
| 06 — Crypto | Cofre, chaves, assinaturas e integridade com bibliotecas consolidadas. | 3–5 semanas |
| 07 — Analytics | Agregações, anomalias, métricas e relatórios. | 3–5 semanas |
| 08 — Dashboard | Telas completas, filtros, gráficos e tempo real. | 4–6 semanas |
| 09 — Segurança | Auditoria, testes de carga, resiliência e correções. | 4–6 semanas |
| 10 — Lançamento | Documentação, empacotamento, backup e demonstração. | 2–4 semanas |

Estimativa global orientativa: aproximadamente 8–14 meses de trabalho individual, sujeita a alteração conforme profundidade, disponibilidade e resultados técnicos. As estimativas por fase não são necessariamente somáveis de forma linear.

## 10.1 Definition of Done por módulo

- Requisitos funcionais e não funcionais aprovados.

- Código implementado e revisado.

- Testes unitários e de integração relevantes aprovados.

- Testes de contrato e falhas aplicáveis aprovados.

- Revisão de segurança concluída.

- Logs, métricas e health checks necessários disponíveis.

- Documentação de uso, configuração e arquitetura atualizada.

- Critérios de aceitação demonstrados em ambiente de laboratório.

# 11. Qualidade, métricas e testes

| Métrica de laboratório | Meta inicial proposta | Como medir |
|---|---|---|
| Disponibilidade durante teste local | 99% no cenário de teste definido. | Sonda periódica e janela documentada. |
| Latência API simples | P95 abaixo de 300 ms. | Teste de carga com ambiente fixo. |
| Processamento de eventos | 100 eventos/s como baseline inicial. | Gerador de eventos sintéticos. |
| Eventos confirmados | Sem perda nos cenários de recuperação definidos. | Teste de falha e reconciliação. |
| Cobertura de caminhos críticos | 90% como meta inicial. | Cobertura automatizada e revisão de casos. |
| Recuperação | Estado consistente após reinício. | Teste de crash/restart e reconciliação. |

Essas metas são objetivos, não garantias. Devem ser recalibradas com base no hardware real e no perfil de carga. Cobertura de testes não substitui revisão de qualidade.

## 11.1 Tipos de teste

- Unitário: função ou classe isolada.

- Integração: comunicação real entre componentes e banco.

- Contrato: compatibilidade de API e envelope de evento.

- Ponta a ponta: fluxo completo de usuário.

- Carga: vazão, latência e consumo de recursos.

- Resiliência: reinício, indisponibilidade, retentativa e recuperação.

- Segurança: autenticação, autorização, validação, dependências e exposição de dados.

# 12. Organização do repositório e documentação

```
ARES/
├── backend/
│   ├── app/
│   │   ├── core/
│   │   ├── api/
│   │   ├── auth/
│   │   ├── audit/
│   │   ├── events/
│   │   └── main.py
│   └── tests/
├── engines/
│   ├── network/
│   ├── threat/
│   ├── endpoint/
│   ├── forensics/
│   ├── crypto/
│   └── analytics/
├── frontend/
├── infrastructure/
│   ├── docker/
│   └── database/
├── docs/
│   ├── architecture/
│   ├── api/
│   ├── security/
│   └── adr/
├── scripts/
├── .env.example
├── .gitignore
├── docker-compose.yml
└── README.md
```

A estrutura é indicativa. Diretórios podem ser introduzidos quando houver conteúdo real; evitar pastas vazias e abstrações prematuras.

## 12.1 Branches e commits

| Convenção | Uso |
|---|---|
| main | Versão estável. |
| develop | Integração contínua de funcionalidades, se o fluxo justificar. |
| feature/* | Funcionalidade nova. |
| fix/* | Correção. |
| refactor/* | Refatoração sem mudança funcional intencional. |
| docs/* | Documentação. |
| feat: | Commit de funcionalidade. |
| fix: | Commit de correção. |
| test: | Commit de testes. |
| security: | Correção ou melhoria de segurança. |
| docs: | Alteração documental. |

## 12.2 Documentos obrigatórios

| Arquivo | Conteúdo |
|---|---|
| README.md | Visão geral, requisitos, instalação, execução e links. |
| ARCHITECTURE.md | Arquitetura e limites de componentes. |
| DATABASE.md | Entidades, relações, índices e migrações. |
| API.md | Rotas, autenticação, esquemas, erros e exemplos. |
| SECURITY.md | Política de segurança e reporte de vulnerabilidades. |
| THREAT_MODEL.md | Ativos, ameaças, limites de confiança e mitigação. |
| CONTRIBUTING.md | Padrões de código, testes e contribuição. |
| ROADMAP.md | Fases, marcos e critérios. |
| CHANGELOG.md | Histórico de versões. |
| ADR/ | Decisões arquiteturais registradas. |

# 13. Laboratório, ética e limites operacionais

Todas as capturas, varreduras, simulações e testes deverão ocorrer em equipamentos, redes, VMs e aplicações controladas pelo desenvolvedor ou para as quais exista autorização explícita.

- Manter redes de laboratório separadas da rede de uso cotidiano quando possível.

- Usar dados sintéticos ou anonimizados para desenvolvimento e demonstração.

- Não coletar conteúdo privado desnecessário.

- Não testar exploração, força bruta ou indisponibilidade contra sistemas de terceiros.

- Documentar escopo, autorização, janela e objetivo dos testes.

- Usar snapshots e cópias para experimentos forenses.

- Garantir que ferramentas de simulação sejam claramente identificadas e desativadas fora do laboratório.

# 14. Arquitetura detalhada do ARES Core

Esta seção define o desenho proposto do núcleo central. O Core será a fronteira de controle da plataforma: identidade, autorização, API, configuração, auditoria, registro de módulos, observabilidade e acesso controlado aos dados.

## 14.1 Responsabilidades e não responsabilidades

| O Core DEVE | O Core NÃO DEVE |
|---|---|
| Autenticar usuários e agentes. | Executar análise profunda de pacotes. |
| Autorizar operações e recursos. | Implementar regras especializadas de detecção. |
| Expor API versionada. | Fazer recuperação forense diretamente. |
| Gerenciar configuração e módulos. | Armazenar segredos em texto puro. |
| Registrar auditoria e estado operacional. | Executar comandos arbitrários em endpoints. |
| Orquestrar fluxos e fornecer dados à UI. | Confiar em autorização feita apenas no frontend. |

## 14.2 Componentes internos

| Componente | Responsabilidades | Interfaces internas |
|---|---|---|
| API Gateway / Router | Receber HTTP, validar entrada, aplicar dependências de autenticação e encaminhar casos de uso. | Rotas versionadas e serviços de aplicação. |
| Identity Service | Usuários, credenciais, MFA e identidade de agentes. | Login, logout, verificação de identidade. |
| Session Service | Criar, renovar, expirar e revogar sessões/tokens. | Sessões e contexto de autenticação. |
| Authorization Service | Resolver papéis e permissões por recurso/ação. | authorize(subject, action, resource). |
| Module Registry | Registrar módulos, versão, capacidades e heartbeat. | Registro, consulta e status. |
| Configuration Service | Validar configurações e separar segredos de parâmetros comuns. | Leitura e atualização controlada. |
| Audit Service | Registrar ações sensíveis e resultados. | Evento de auditoria imutável por aplicação. |
| Event Ingress | Validar envelope e publicar eventos aceitos. | Contrato de evento versionado. |
| Health/Observability | Health checks, readiness, métricas e logs. | /health, /ready e métricas internas. |
| Persistence Layer | Acesso a repositórios e transações. | Interfaces de repositório; sem SQL espalhado nas rotas. |

## 14.3 Fluxo de requisição

```
Cliente
  -> HTTPS / reverse proxy (se implantado)
  -> Middleware de request-id e limites
  -> Roteador API /api/v1
  -> Autenticação
  -> Autorização por ação/recurso
  -> Validação de entrada
  -> Caso de uso / serviço de aplicação
  -> Repositório / Event Bus
  -> Resposta padronizada + log correlacionado
```

A ordem exata de middlewares e validações será definida na implementação, mas nenhuma operação protegida poderá executar antes da autenticação e autorização adequadas. Endpoints públicos, como health, terão escopo mínimo e não revelarão informações internas sensíveis.

## 14.4 Autenticação

### 14.4.1 Usuários

- Login por e-mail ou identificador definido no cadastro.

- Senha armazenada somente como hash Argon2id com parâmetros calibrados para o ambiente.

- Mensagens de falha que não revelem se uma conta existe.

- Limitação de tentativas e atraso progressivo, com monitoramento de abuso.

- MFA com TOTP como opção inicial; códigos de recuperação armazenados como hashes.

- Recuperação de conta com tokens de uso único, expiração curta e revogação de sessões conforme política.

- Conta administrativa inicial criada por procedimento seguro de bootstrap, não por credencial padrão fixa.

### 14.4.2 Sessões

A sessão deverá ser revogável e ter expiração definida. Se a aplicação web usar cookies, eles deverão ser Secure, HttpOnly e SameSite adequado; proteção CSRF será necessária para operações autenticadas por cookie. Se forem usados tokens bearer, a estratégia de armazenamento, rotação, expiração e revogação deverá ser documentada, evitando armazenamento inseguro no navegador.

### 14.4.3 Agentes

Agentes terão identidade própria, credencial ou certificado por instalação, rotação e revogação individual. Um agente não será tratado como usuário humano e não receberá permissões administrativas.

## 14.5 Autorização RBAC

O modelo inicial será RBAC, com autorização no servidor e permissões atômicas por ação e recurso. A UI poderá esconder opções não autorizadas, mas isso é apenas conveniência; a API sempre revalida.

| Papel | Capacidades gerais propostas |
|---|---|
| Super Admin | Gerenciar usuários, papéis, configuração global e módulos. |
| Security Admin | Configurar motores, políticas e fontes de telemetria. |
| Security Analyst | Investigar alertas, gerenciar incidentes e consultar evidências autorizadas. |
| Auditor | Consultar trilhas, relatórios e histórico sem alterar configurações. |
| Viewer | Consultar painéis e informações liberadas. |

Permissões iniciais sugeridas: users.read/write, roles.manage, modules.read/configure, alerts.read/triage, incidents.read/write, evidence.read/export, audit.read, reports.generate, settings.manage. A lista final deverá ser granular e evitar permissões excessivamente amplas.

## 14.6 Gestão de módulos

Cada módulo deverá declarar nome, versão, versão de contrato compatível, capacidades, estado e mecanismo de heartbeat. O Core manterá estados como starting, healthy, degraded, unavailable e stopped. Um heartbeat expirado não deve ser interpretado como prova de encerramento; deve produzir estado de indisponibilidade com timestamp da última observação.

## 14.7 Configuração e segredos

- Configuração não secreta pode ser versionada e validada por esquema.

- Segredos não entram no Git, logs, mensagens de erro ou respostas da API.

- Arquivo .env.example conterá apenas nomes e exemplos fictícios.

- Ambientes dev/test/prod terão configurações separadas.

- Alterações de configuração crítica exigirão autorização e auditoria.

- Rotação de credenciais e chaves deverá ter procedimento documentado.

## 14.8 Logs e auditoria

Logs operacionais devem ser estruturados, com timestamp UTC, nível, serviço, request_id, event_id quando aplicável e mensagem. Não devem conter senha, token, segredo MFA, chave privada ou conteúdo sensível desnecessário.

A auditoria deve registrar ator, ação, recurso, resultado, timestamp, origem contextual permitida e correlation_id. A aplicação deve dificultar alterações silenciosas; para garantias fortes de imutabilidade será necessário armazenamento append-only ou externo protegido.

## 14.9 Tratamento de erros

| Classe | Comportamento |
|---|---|
| 400 — Bad Request | Entrada inválida ou parâmetro incompatível; resposta com código de erro estável. |
| 401 — Unauthorized | Ausência ou invalidade de autenticação. |
| 403 — Forbidden | Identidade válida sem permissão. |
| 404 — Not Found | Recurso inexistente ou não revelável conforme política. |
| 409 — Conflict | Conflito de estado, versão ou operação duplicada. |
| 422 — Validation Error | Dados não passam validação de esquema. |
| 429 — Too Many Requests | Limite de requisições excedido. |
| 500 — Internal Error | Erro inesperado; mensagem genérica ao cliente e detalhes apenas nos logs protegidos. |
| 503 — Unavailable | Dependência essencial indisponível. |

## 14.10 Observabilidade e saúde

- GET /health: processo está vivo, sem expor detalhes internos.

- GET /ready: dependências essenciais prontas para receber tráfego.

- Métricas internas: latência, taxa de erro, requisições, fila, eventos e heartbeat.

- Logs correlacionados por request_id e correlation_id.

- Estado de módulos com timestamp da última atualização.

- Alertas operacionais para falhas repetidas, fila acumulada e armazenamento indisponível.

# 15. Contratos de API propostos

Os endpoints abaixo são uma proposta inicial, não um contrato congelado. Todos os endpoints de negócio ficarão sob /api/v1. Os exemplos não incluem tokens ou segredos.

| Método e rota | Finalidade | Acesso inicial |
|---|---|---|
| GET /health | Liveness simples. | Público/local; sem detalhes sensíveis. |
| GET /ready | Readiness das dependências essenciais. | Interno/admin conforme implantação. |
| POST /api/v1/auth/login | Autenticar usuário. | Público com rate limit. |
| POST /api/v1/auth/logout | Encerrar sessão. | Usuário autenticado. |
| POST /api/v1/auth/mfa/verify | Validar segundo fator. | Fluxo de autenticação. |
| POST /api/v1/auth/recovery | Iniciar recuperação. | Público com proteção contra abuso. |
| GET /api/v1/me | Consultar identidade e permissões efetivas. | Usuário autenticado. |
| GET /api/v1/modules | Listar módulos e estados. | modules.read. |
| GET /api/v1/events | Consultar eventos com filtros e paginação. | events.read. |
| GET /api/v1/alerts | Consultar alertas. | alerts.read. |
| GET /api/v1/incidents | Consultar incidentes. | incidents.read. |
| GET /api/v1/audit-logs | Consultar auditoria. | audit.read. |
| GET /api/v1/system/info | Informações não sensíveis da plataforma. | Admin/operacional; revisar exposição. |

## 15.1 Padrões de API

- JSON como formato padrão.

- Timestamps em UTC e formato ISO 8601.

- IDs opacos e estáveis, preferencialmente UUID.

- Paginação explícita, com limite máximo por página.

- Filtros e ordenação por campos permitidos, nunca SQL arbitrário.

- Formato de erro consistente com code, message, details seguros e request_id.

- Idempotency-Key em operações que possam ser repetidas com risco de duplicação.

- Versionamento de API e esquemas de evento.

## 15.2 Exemplo de resposta de erro

```
{
  "error": {
    "code": "permission_denied",
    "message": "A operação não é permitida.",
    "request_id": "uuid"
  }
}
```

# 16. Modelo de dados inicial

O desenho relacional será refinado antes das migrações. As relações abaixo são conceituais.

| Entidade | Campos conceituais | Relações |
|---|---|---|
| User | id, email, display_name, password_hash, status, created_at | N:N com Role; 1:N com Session. |
| Role | id, name, description | N:N com User e Permission. |
| Permission | id, resource, action | N:N com Role. |
| Session | id, user_id, created_at, expires_at, revoked_at | N:1 com User. |
| Device | id, hostname, platform, first_seen, last_seen, status | 1:N com Agent e Event. |
| Agent | id, device_id, credential_ref, version, last_heartbeat, status | N:1 com Device. |
| Event | event_id, type, source, occurred_at, observed_at, payload_ref | Pode referenciar Device e Alert. |
| Alert | id, rule_id, severity, confidence, status, created_at | N:1 com Rule; N:N com Event. |
| Incident | id, title, severity, status, owner_id, opened_at, closed_at | N:N com Alert e Evidence. |
| Rule | id, name, version, definition, enabled | 1:N com Alert. |
| Evidence | id, hash, size, type, storage_ref, acquired_at, custodian_id | N:N com Incident. |
| AuditLog | id, actor_id, action, resource, result, timestamp, correlation_id | N:1 opcional com User. |

## 16.1 Integridade e migrações

- Chaves estrangeiras e restrições para estados válidos.

- Índices definidos a partir de consultas reais e métricas.

- Migrações versionadas e testadas em banco temporário.

- Política de exclusão/anonimização para dados pessoais.

- Transações para operações que atualizam múltiplas entidades.

- Não armazenar payload ilimitado ou binários grandes em tabelas operacionais.

# 17. Modelo de ameaças do Core

| Ativo | Ameaça | Mitigação principal |
|---|---|---|
| Credenciais | Roubo, brute force, reutilização. | Argon2id, MFA, rate limit, recuperação segura. |
| Sessões | Roubo, replay, fixation. | Cookies seguros ou tokens bem geridos, expiração, rotação e revogação. |
| API | Acesso indevido, injection, abuso. | Autorização por endpoint/recurso, validação, limites e testes. |
| Banco | Exposição, alteração, indisponibilidade. | Privilégios mínimos, backups, migrações e segredos protegidos. |
| Agentes | Falsificação ou credencial comprometida. | Identidade por agente, rotação e revogação. |
| Eventos | Falsificação, replay, duplicação e payload malicioso. | Autenticação da origem, schema validation, idempotência e limites. |
| Auditoria | Apagamento ou adulteração. | Acesso restrito, append-only e cópia protegida. |
| Configuração | Alteração maliciosa ou vazamento de segredo. | RBAC, revisão, auditoria e secret management. |
| Dependências | Pacote vulnerável ou comprometido. | Lockfiles, atualização, análise de dependências e revisão. |

## 17.1 Abuso de privilégios

O modelo deve considerar administrador mal-intencionado ou conta administrativa comprometida. A plataforma deve limitar privilégios, registrar ações, separar funções quando possível e tornar alterações críticas rastreáveis. Nenhum mecanismo local garante proteção absoluta contra um administrador do próprio host.

## 17.2 Privacidade e minimização

Coletar apenas os dados necessários para a finalidade de segurança definida. Documentar quais dados o agente coleta, por que, por quanto tempo e quem pode consultá-los. Dados pessoais e conteúdo de comunicações exigem cuidado especial e autorização apropriada.

# 18. Plano de testes do ARES Core

| Área | Casos mínimos |
|---|---|
| Autenticação | Senha correta/incorreta; conta desativada; rate limit; MFA válido/inválido; recuperação expirada. |
| Sessões | Expiração; logout; revogação; uso de sessão revogada; concorrência de renovação. |
| Autorização | Cada papel em cada operação sensível; acesso horizontal a recurso alheio; acesso vertical. |
| API | Entrada malformada; campos extras; limites; paginação; filtros inválidos; erros internos. |
| Auditoria | Registro de sucesso/falha; ator correto; ausência de segredos; correlação. |
| Eventos | Evento inválido; duplicado; versão incompatível; payload excessivo; consumidor indisponível. |
| Persistência | Rollback; falha de conexão; migração; integridade referencial; backup/restauração. |
| Resiliência | Reinício; dependência indisponível; retentativa; dead-letter; readiness. |
| Segurança | CSRF se cookie; CORS; rate limit; exposição de stack trace; autorização server-side. |

## 18.1 Critérios de aceite do Core

- Um usuário autorizado consegue autenticar-se e encerrar a sessão.

- MFA pode ser habilitado e validado conforme política definida.

- A API bloqueia operações não autorizadas independentemente da interface.

- Papéis e permissões são administráveis e auditáveis.

- Eventos válidos são aceitos e eventos inválidos são rejeitados com erro controlado.

- O sistema registra ações sensíveis sem expor segredos.

- Health e readiness refletem corretamente o estado do serviço.

- Testes automatizados cobrem fluxos positivos, negativos e de autorização.

- Documentação de API e decisões de arquitetura está atualizada.

# 19. Decisões confirmadas, propostas e questões em aberto

## 19.1 Confirmado pelo projeto

- Nome de trabalho: ARES Cyber Defense Platform.

- Objetivo: plataforma de cibersegurança defensiva e modular.

- Desenvolvimento feito pelo assistente (Claude) a pedido do autor; o autor revisa antes de cada merge em `main`. Alteração de 26/11/2026, registrada na versão 1.2 do histórico. Substitui a versão anterior, que previa desenvolvimento manual pelo usuário.

- Ambiente principal: Windows; memória RAM informada: 16 GB; nível de programação: avançado.

- Plataforma-alvo: Windows e Linux, com interface web.

- Preferência por ferramentas gratuitas e open source.

- Escopo inclui Core, Network, Threat, Endpoint, Forensics, Crypto, Analytics e Dashboard.

## 19.2 Propostas técnicas ainda revisáveis

- Python/FastAPI para Core e API.

- Rust para componentes de baixo nível quando houver justificativa.

- React + TypeScript para frontend.

- PostgreSQL como banco principal.

- Redis como componente opcional de cache/fila.

- Docker e WSL 2 para ambiente de desenvolvimento.

- RBAC como modelo inicial de autorização.

- Monólito modular como primeira arquitetura de execução.

- Argon2id para hashes de senha.

## 19.3 Questões em aberto

- Versão exata do Windows e edição (Home/Pro).

- CPU, espaço livre em disco e suporte à virtualização.

- O ARES será inicialmente single-user local ou multiusuário desde o primeiro marco?

- O primeiro agente será Windows Service ou processo executado pelo usuário?

- A comunicação agente-servidor começará por HTTPS polling ou canal persistente?

- Quais fontes de eventos do Windows serão coletadas inicialmente?

- Qual será o modelo final de sessão web: cookie seguro ou bearer token com estratégia de armazenamento definida?

- Qual licença open source será adotada para o código do ARES?

- Quais dados serão considerados sensíveis e qual política de retenção será aplicada?

# 20. Glossário e referências

| Termo | Definição |
|---|---|
| SIEM | Security Information and Event Management; coleta, correlação e análise de eventos de segurança. |
| EDR | Endpoint Detection and Response; monitoramento e investigação em endpoints. |
| IOC | Indicator of Compromise; indicador associado a possível comprometimento. |
| RBAC | Role-Based Access Control; controle de acesso baseado em papéis. |
| MFA | Multi-Factor Authentication; autenticação com mais de um fator. |
| Event Bus | Mecanismo de distribuição de eventos entre produtores e consumidores. |
| Idempotência | Propriedade que permite repetir uma operação sem duplicar seu efeito. |
| Dead-letter queue | Fila para mensagens que não puderam ser processadas após a política de tentativas. |
| Chain of custody | Registro rastreável de aquisição, acesso e transferência de evidências. |
| IOC confidence | Grau de confiança de que um indicador ou evento é relevante. |
| P95 | Percentil 95 de uma distribuição de latência. |

## 20.1 Documentação e recursos gratuitos

| Recurso | Uso | URL |
|---|---|---|
| Python | Linguagem e biblioteca padrão. | https://docs.python.org/3/ |
| FastAPI | API backend. | https://fastapi.tiangolo.com/ |
| Rust Book | Aprendizado de Rust. | https://doc.rust-lang.org/book/ |
| PostgreSQL | Banco de dados. | https://www.postgresql.org/docs/ |
| React | Frontend. | https://react.dev/learn |
| TypeScript | Tipagem frontend. | https://www.typescriptlang.org/docs/ |
| OWASP | Boas práticas de segurança de aplicações. | https://owasp.org/ |
| MITRE ATT&CK | Base de conhecimento de táticas e técnicas. | https://attack.mitre.org/ |
| NIST CSF | Framework de cibersegurança. | https://www.nist.gov/cyberframework |
| Suricata | IDS/IPS e análise de rede. | https://suricata.io/ |
| Zeek | Monitoramento e análise de rede. | https://zeek.org/ |
| Wireshark | Análise de protocolos. | https://www.wireshark.org/docs/ |
| Wazuh | Segurança e monitoramento de endpoints. | https://documentation.wazuh.com/ |
| OWASP Juice Shop | Aplicação vulnerável para laboratório. | https://owasp.org/www-project-juice-shop/ |
| PortSwigger Academy | Treinamento gratuito de segurança web. | https://portswigger.net/web-security |
| OverTheWire | Desafios educacionais. | https://overthewire.org/wargames/ |
| WSL | Instalação e uso do Linux no Windows. | https://learn.microsoft.com/windows/wsl/install |
| Docker Desktop | Contêineres no Windows. | https://docs.docker.com/desktop/ |

# Apêndice A — Primeira entrega documental

Antes de iniciar a implementação, o primeiro pacote de engenharia deverá conter:

- Revisão e aprovação desta especificação.

- ADR para arquitetura inicial (monólito modular).

- Diagrama de componentes do Core.

- Diagrama de sequência de login e autorização.

- Modelo entidade-relacionamento inicial.

- Contrato OpenAPI inicial.

- Esquema de evento v1.

- Threat model inicial do Core.

- Plano de testes e critérios de aceite.

# Apêndice B — Política de evolução deste documento

Toda mudança relevante deverá registrar: identificador da alteração, data, seção afetada, motivo, impacto, responsável e status. A versão 1.0 é a baseline inicial. Alterações menores podem gerar 1.1, 1.2 etc.; mudanças estruturais relevantes podem justificar versão 2.0.

| Versão | Data | Alteração |
|---|---|---|
| 1.0 | 26/11/2026 | Primeira especificação consolidada do produto e arquitetura proposta do ARES Core. |

> Próxima etapa recomendada — Revisar e fechar as decisões em aberto da seção 19.3. Em seguida, produzir os artefatos de arquitetura do Core (diagramas, modelo relacional e contrato OpenAPI) antes de iniciar a implementação.

# 21. O que precisamos fechar antes de programar

Esta seção é o checklist oficial de pré-implementação do ARES. A ideia é evitar começar a escrever código com decisões fundamentais indefinidas. Nem todos os detalhes precisam ser resolvidos para sempre: cada item deve ter uma decisão inicial documentada, responsável e critério de revisão.

Regra de avanço: uma etapa só é considerada pronta quando suas decisões estão registradas, os riscos conhecidos foram avaliados e os critérios de saída foram atendidos. Itens não aplicáveis devem ser marcados como N/A com justificativa.

## 21.1 Ambiente e capacidade da máquina

- Confirmar a versão e edição do Windows (Windows 10/11; Home/Pro) e o número da build.

- Verificar processador, quantidade de núcleos, memória disponível e espaço livre em disco.

- Confirmar se a virtualização por hardware está habilitada no firmware.

- Decidir se o desenvolvimento Linux será feito via WSL 2, VM ou instalação separada.

- Definir a distribuição Linux e sua versão suportada.

- Decidir se Docker será usado desde o início ou somente quando houver necessidade.

- Definir limites de CPU, RAM e disco para WSL/Docker considerando a máquina de 16 GB.

- Definir onde ficarão repositório, banco de desenvolvimento, logs e evidências de laboratório.

- Criar uma estratégia de backup do repositório e dos dados locais de desenvolvimento.

- Registrar versões exatas das ferramentas depois de instaladas e validadas.

## 21.2 Linguagens, frameworks e versões

- Confirmar Python como linguagem principal do Core e definir uma versão suportada.

- Confirmar FastAPI para a API e escolher o servidor ASGI e sua configuração.

- Decidir em que momento Rust será introduzido e quais componentes justificariam seu uso.

- Confirmar React e TypeScript para o Dashboard ou documentar alternativa.

- Definir gerenciadores de dependências e lockfiles para backend e frontend.

- Definir política de atualização: versões fixas, janela de atualização e testes de compatibilidade.

- Verificar licenças das dependências e manter inventário de componentes de terceiros.

## 21.3 Arquitetura de execução e limites entre módulos

- Confirmar monólito modular como arquitetura da primeira versão.

- Definir quais módulos serão bibliotecas/pacotes internos e quais poderão rodar como processos separados.

- Definir estrutura de pastas e regras de dependência entre camadas.

- Definir interfaces públicas de cada módulo e proibir acesso direto às tabelas internas de outros módulos.

- Definir como módulos são inicializados, encerrados, monitorados e atualizados.

- Definir política de compatibilidade de versões de módulos e contratos.

- Definir quando uma necessidade de desempenho ou isolamento justifica separar um processo.

- Registrar as decisões relevantes em ADRs antes de implementar decisões difíceis de reverter.

## 21.4 Backend, API e contratos

- Definir organização das camadas: rotas, esquemas, casos de uso/serviços, domínio e repositórios.

- Definir convenções de nomes, validação, tipagem, tratamento de exceções e logging.

- Definir versionamento da API e política de compatibilidade.

- Fechar o primeiro contrato OpenAPI com rotas essenciais do Core.

- Definir formato padrão de sucesso, paginação, filtros, ordenação e erros.

- Definir limites de tamanho para requisições, payloads, uploads e paginação.

- Definir política de CORS, CSRF (se aplicável), rate limiting e timeouts.

- Definir como será feita autenticação entre serviços internos e agentes.

- Definir estratégia de idempotência para operações repetíveis.

- Definir quais endpoints serão públicos, internos, administrativos ou de agente.

## 21.5 Banco de dados e persistência

- Confirmar PostgreSQL como banco inicial e fixar versão suportada.

- Desenhar o diagrama entidade-relacionamento da primeira versão.

- Definir chaves primárias, estrangeiras, restrições, índices e regras de exclusão.

- Definir ferramenta e convenção de migrações.

- Definir estratégia de transações e limites de consistência.

- Definir como serão armazenados eventos: tabelas relacionais, partições ou armazenamento separado conforme volume medido.

- Definir armazenamento de arquivos/evidências fora das tabelas comuns e seu mapeamento por metadados.

- Definir retenção, arquivamento, descarte e anonimização de dados.

- Definir backup, restauração e testes periódicos de recuperação.

- Definir usuário e permissões do banco com privilégio mínimo.

## 21.6 Identidade, autenticação e autorização

- Decidir se a primeira versão será single-user local ou multiusuário desde o início.

- Definir o procedimento seguro de criação do primeiro administrador.

- Definir identificador de login (e-mail, username ou ambos).

- Definir política de senha e parâmetros calibrados de Argon2id.

- Definir MFA inicial (por exemplo, TOTP), recuperação e códigos de backup.

- Escolher o modelo de sessão web: cookie seguro ou bearer token, incluindo armazenamento, expiração, rotação e revogação.

- Definir expiração por inatividade e duração máxima da sessão.

- Definir proteção contra brute force, credential stuffing e enumeração de contas.

- Fechar papéis iniciais e matriz papel-permissão.

- Definir autorização por ação e recurso, incluindo propriedade/escopo de cada registro.

- Definir identidade, credencial, rotação e revogação individual dos agentes.

- Definir trilha de auditoria para login, logout, MFA, recuperação, alteração de papel e operações administrativas.

## 21.7 Event Bus e comunicação

- Definir o envelope de evento v1 e seu schema formal.

- Definir campos obrigatórios, timestamps, timezone, IDs, origem, versão e classificação.

- Definir taxonomia de event_type e convenção de nomes.

- Definir limites de payload e política para dados pessoais ou segredos.

- Escolher o mecanismo inicial: chamadas internas, fila simples ou broker; justificar a escolha.

- Definir persistência, confirmação, retentativa, backoff e dead-letter.

- Definir idempotência, deduplicação e tratamento de replay.

- Definir quais fluxos exigem ordenação e quais podem ser processados fora de ordem.

- Definir estratégia de evolução e compatibilidade de schemas.

- Definir como testar perda, duplicação, atraso e indisponibilidade de consumidores.

## 21.8 Segurança, privacidade e modelo de ameaças

- Identificar ativos críticos, atores, limites de confiança e superfícies de ataque.

- Revisar o threat model do Core e criar um registro de riscos priorizados.

- Definir gestão de segredos, armazenamento local, rotação e política de exposição.

- Definir TLS e autenticação mútua ou equivalente para agentes, conforme arquitetura.

- Definir política de logs para nunca registrar senhas, tokens, segredos MFA ou chaves privadas.

- Definir política de atualização e verificação de dependências.

- Definir permissões mínimas para o processo do Core e agentes.

- Definir dados coletados por cada agente, finalidade, retenção e acesso.

- Definir como serão protegidos backups, evidências e exportações.

- Definir procedimento para reporte e correção de vulnerabilidades.

- Definir limites de escopo do laboratório e confirmar autorização para todos os testes.

## 21.9 Frontend e experiência do usuário

- Definir estrutura do frontend e estratégia de rotas.

- Definir biblioteca de componentes e padrões visuais básicos.

- Definir gerenciamento de estado e cache de dados remotos.

- Definir tratamento de sessão expirada e permissões insuficientes.

- Definir estados de carregamento, erro, vazio, desconectado e dado desatualizado.

- Definir acessibilidade mínima: teclado, foco, contraste e rótulos.

- Definir atualização em tempo real: polling inicial ou WebSocket/SSE quando necessário.

- Definir política para esconder ações na interface sem substituir a autorização no servidor.

## 21.10 Testes, qualidade e entrega

- Escolher ferramentas de testes backend, frontend, contrato e ponta a ponta.

- Definir estrutura de testes e convenção de nomes.

- Definir critérios mínimos para testes unitários e de integração por módulo.

- Criar testes negativos de autenticação, autorização e validação desde o início.

- Definir lint, formatação, análise estática e verificação de tipos.

- Definir pipeline local ou CI gratuito para executar testes e verificações.

- Definir metas iniciais realistas de latência, vazão e uso de memória.

- Definir critérios de aceite do primeiro incremento do Core.

- Definir política de versionamento, tags e changelog.

- Definir como gerar uma instalação local repetível e como restaurar o sistema.

## 21.11 Organização do trabalho e documentação

- Criar repositório Git e configurar .gitignore e proteção contra commit de segredos.

- Criar README inicial com propósito, requisitos e status real do projeto.

- Criar diretório docs e diretório ADR.

- Criar quadro de tarefas com épicos, histórias, critérios de aceite e dependências.

- Definir convenção de branches e commits.

- Definir que cada módulo terá README, contrato, testes e instruções de configuração.

- Registrar decisões e mudanças no documento principal, mantendo histórico de versões.

- Separar claramente requisitos confirmados, propostas e questões ainda abertas.

## 21.12 Critério de autorização para começar a implementação

A implementação do ARES Core pode começar quando os itens abaixo estiverem concluídos ou explicitamente aceitos como decisões provisórias:

- Ambiente de desenvolvimento instalado e validado, com versões registradas.

- Repositório criado, estrutura inicial definida e proteção contra segredos configurada.

- Arquitetura de monólito modular aprovada e limites do Core definidos.

- Modelo ER inicial revisado e estratégia de migrações definida.

- Contrato OpenAPI mínimo revisado.

- Fluxo de autenticação, sessão, MFA inicial e matriz RBAC documentados.

- Envelope de eventos v1 definido, mesmo que o broker definitivo fique para depois.

- Threat model inicial e requisitos de logging/auditoria aprovados.

- Estratégia de testes e critérios de aceite do primeiro marco definidos.

- Lista de tarefas da primeira iteração priorizada e estimada.

Se um item ainda não puder ser decidido, registrar: (a) o que falta saber, (b) alternativas consideradas, (c) risco de adiar e (d) quando a decisão será revisitada. Não transformar incerteza em decisão silenciosa.

## 21.13 Primeira iteração recomendada após o checklist

| Ordem | Entrega verificável | Não incluir ainda |
|---|---|---|
| 1 | Repositório, estrutura mínima, ambiente e documentação base. | Microserviços, Kubernetes ou automações complexas. |
| 2 | Aplicação Core inicial com configuração e health/readiness. | Lógica especializada de todos os engines. |
| 3 | Conexão PostgreSQL e primeira migração testada. | Otimização prematura e particionamento sem dados. |
| 4 | Identidade, login, sessão e autorização mínima. | Recursos avançados de administração sem necessidade. |
| 5 | Auditoria e logs estruturados. | Dashboards analíticos completos. |
| 6 | Contrato e ingestão inicial de eventos. | Broker distribuído antes de medir a necessidade. |
| 7 | Testes de integração e recuperação do Core. | Agente endpoint completo ou detecção avançada. |

O primeiro marco será considerado concluído quando o Core iniciar de forma repetível, validar sua configuração, conectar-se ao banco, autenticar um usuário de teste, aplicar permissões no backend, registrar ações sensíveis e passar pelos testes automatizados definidos.

# Histórico de versões atualizado

| Versão | Data | Alteração |
|---|---|---|
| 1.0 | 26/11/2026 | Especificação geral e arquitetura proposta do ARES Core. |
| 1.1 | 26/11/2026 | Inclusão do checklist detalhado de pré-implementação, critérios para liberar o início da programação e primeira iteração recomendada. |
| 1.2 | 26/11/2026 | Seção 19.1: desenvolvimento passa a ser feito pelo assistente (Claude) a pedido do autor, com revisão do autor antes de cada merge. Motivo: decisão do autor. Impacto: CLAUDE.md seção 3 e skill model-routing já alinhados. Responsável: autor. Status: confirmado pelo autor em 26/11/2026. Versão em `.docx` não atualizada; este `.md` é a versão de trabalho. |
