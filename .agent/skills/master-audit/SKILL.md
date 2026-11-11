---
name: master-audit
description: Master Skill de Supervisão e Auditoria. Executa o comando herói `atlas audit` para gerar relatórios de maturidade (EMI) e saúde do repositório.
version: 1.0.0
sub_skills:
  - vulnerability-scanner
  - lint-and-validate
  - database-design
  - testing-patterns
  - frontend-design
  - performance-profiling
---

# Master Audit Skill (The Hero Command)

Esta Master Skill é a autoridade máxima em governança no ecossistema Atlas. Ela orquestra todas as validações técnicas para gerar um diagnóstico de negócio para CTOs e Leads.

## 🚀 Hero Workflow: `atlas audit` (Enterprise Tier)

Quando o usuário invoca `atlas audit`, esta skill executa obrigatoriamente a Auditoria de Espectro Total:

1.  **Orquestração Enterprise**: Dispara o script mestre `atlas_full_audit.py` (v3.0).
2.  **Contexto do projeto**: Consulte a [visão geral do Dalion](../../../docs/00-overview.md) e apresente somente métricas verificáveis.
3.  **Business Sync**: Sincroniza KPIs técnicos com `docs/business/` via `business_sync.py`.
4.  **Reporting**: Geração do `ATLAS_FULL_AUDIT_REPORT.md` (Enterprise Tier).

## 📊 Business Readiness Check
A Skill deve validar:
1. Presença de `docs/business/investment_proposal.md`.
2. Sincronia entre o EMI Score técnico e o citado na proposta.
3. Existência de roadmap estratégico atualizado.

## 📊 Estrutura de Valor
- **Visibilidade**: Mostra ao gestor exatamente onde o projeto está forte e onde há gaps.
- **Redução de Dívida**: Identifica arquivos fora do Axioma 023 (>300 linhas).
- **Segurança**: Garante que os axiomas de proteção (JWT, RLS) estão ativos.

## 💡 Princípio Audit
Uma auditoria sem plano de remediação é apenas ruído. Sempre forneça o próximo passo concreto.
