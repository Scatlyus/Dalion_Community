# 🧭 Dalion

> **Multi-agent cybersecurity system with ML-powered threat detection and automated response.**

![Version](https://img.shields.io/badge/version-2.5.0-blue)
![License](https://img.shields.io/badge/license-Proprietary-red)
![Status](https://img.shields.io/badge/status-in%20development-blue)

---

## 🎯 What is Dalion?

**Dalion is a surgical SOC (Security Operations Center) in software.**

It deploys specialized AI agents that work together to detect threats, predict trajectories, and respond automatically.

> **Validation status:** The automated test suite and local KC7 scenarios can be run using the commands in the installation guide. Results depend on the dataset and configuration used.

**Built for:**
- 🏥 **Healthcare** (LGPD/HIPAA compliance)
- 🏦 **Fintech** (Real-time fraud & anomaly detection)
- 🏢 **Enterprises** (Automated SOC scaling)
- 🇧🇷 **Brazilian Markets** (Native LGPD-first architecture)
- 📡 **Telemetry processing** for Suricata EVE events

---

## 🏗️ Architecture Axioms (ATLAS Protocol)

Dalion follows the architectural principles below:

- **AX-DLN-001:** Multi-source enrichment using configured intelligence providers.
- **AX-DLN-002:** Intent-Based Decision Logic (Recon vs. Exploit differentiation).
- **AX-DLN-003:** Systematic EMI Validation (Mandatory regression testing).
- **AX-DLN-004:** Stateful Context Isolation (Host-specific trajectories via `DalionStateContext`).

---

## 🚀 Performance & Scale

- ⚡ **Latency and throughput** depend on workload, configuration and external providers.
- 🏎️ **Stress testing**: run `npx ts-node --transpile-only tools/stress_test_runner.ts <dataset>` to measure the pipeline on your environment.
- 🧩 **Stateful Intelligence**: Native support for time-series analysis (Cronos) and host trajectories.

---

## 🛠️ Core Capabilities

### 12 Specialized Intelligence Agents

**Highlights:**
- **D2 Sentinela** → Real-time anomaly & brute-force detection.
- **D3 Espionagem** → Threat enrichment using multiple sources in sequence.
- **D10 Ethos** → Intent classification (Legitimate vs. Malicious).
- **D12 Rottweiler** → Strategic decision engine with **Trajectory Awareness**.

---

## 📦 Product Tiers & Repositories

Dalion está disponível em tiers modulares para diferentes necessidades de escala:

### 🌱 Community (Open Source)
**Repository:** [`Dalion_Community`](https://github.com/Scatlyus/Dalion_Community)

| Feature | Spec |
|---------|------|
| **Agentes** | 4 agentes (D1, D2, D10, D11) |
| **EMI Validation** | ✅ Básico |
| **Stateful Context** | ❌ (Stateless) |
| **Ideal para** | Labs, POCs, pequenas redes |

---

### 💼 Pro
**Repository:** [`Dalion_Pro`](https://github.com/Scatlyus/Dalion_Pro)

| Feature | Spec |
|---------|------|
| **Agentes** | 8 agentes (D1-D4, D7-D8, D10-D11) |
| **EPS Limit** | ∞ Ilimitado (soft warning 5K) |
| **Features Avançadas** | `suricata_strict`, `executive_reports` |
| **Threat Intel** | 3 fontes externas (VirusTotal, AbuseIPDB, IPInfo) |
| **Attack Prediction** | ❌ |
| **Response Level** | Deterrence (Block + Quarantine) |
| **Suporte** | Email (SLA 48h) |
| **Ideal para** | Empresas médias, compliance básico |

**Agentes Adicionais:**
- **D3 Espionagem** → APT detection + enrichment
- **D4 IntelCampo** → Tactical field intelligence
- **D7 PsySec** → Behavioral profiling
- **D8 ThreatIntel** → Threat scoring

---

### 🏢 Enterprise
**Repository:** [`Dalion_Enterprise`](https://github.com/Scatlyus/Dalion_Enterprise)

| Feature | Spec |
|---------|------|
| **Agentes** | 12 agentes (D1-D12 completos) |
| **EPS Limit** | ∞ Ilimitado (soft warning 5K) |
| **Features Avançadas** | Todas (9 features) |
| **Threat Intel** | 9+ fontes (incluindo custom feeds) |
| **Attack Prediction** | ✅ D9 AttackGraph (predição temporal) |
| **Response Level** | Terminal (Active Response + Isolation) |
| **Suporte** | 24/7 + Slack dedicado + Managed SOC |
| **Ideal para** | Grandes empresas, SOC gerenciado, datacenters |

**Agentes Exclusivos:**
- **D5 Artilharia** → Compliance (LGPD/NIST) + Mutation Lab
- **D6 Diplomacia** → Executive Communication
- **D9 AttackGraph** → Temporal graphs + predictive defense
- **D12 Rottweiler** → Strategic decision engine

**Features Enterprise:**
- `suricata_learn` → Active learning com --learn flag
- `attack_graph` → Predição de próximos passos do adversário
- `mutation_lab` → Testing de payloads maliciosos
- `active_response` → D12 decisão terminal (bite)
- `managed_soc` → Deploy gerenciado pela CodeArk
- `multi_tenant` → Suporte a múltiplos clientes
- `sla_support` → SLA contratual 99.9%

---

### 💡 Sistema de Licenciamento

Todos os tiers usam o **Dalion License System** (`Omega/dalion-license/`):
- ✅ **Validação offline** (zero dependências externas)
- ✅ **Anti-tamper** (HMAC-SHA256 fingerprint)
- ✅ **EPS ilimitado** (soft warning em 5.000 EPS para monitoramento de performance)
- ✅ **Diferenciação por agentes e features**, não por volume

**Inicialização:**
```typescript
import { licenseManager } from '@dalion/license';

// Bootstrap (uma vez no início)
licenseManager.initialize(); // Lê de DALION_LICENSE_KEY env var

// Verificação em runtime (nos agentes)
licenseManager.requireAgent('D9'); // Lança erro se não autorizado
licenseManager.requireFeature('attack_graph');
```

---


## 🏗️ Architecture (Linear Pipeline)
```mermaid
graph TD
    Input[Suricata EVE] --> D2[D2 Sentinela<br/>(Heuristics)]
    D2 --> D3[D3 Espionagem<br/>(Enrichment)]
    D3 --> D8[D8 ThreatIntel<br/>(Lookup)]
    D8 --> D4[D4 IntelCampo<br/>(Tactical)]
    D4 --> D7[D7 PsySec<br/>(Profiling)]
    D7 --> D10[D10 Ethos<br/>(Classification)]
    D10 --> D12[D12 Rottweiler<br/>(Decision)]
    D12 --> D1[D1 Infantaria<br/>(Execution)]
    D1 --> D11[D11 AfterAction<br/>(Feedback Loop)]
    D11 -.->|Reinforcement Signals| D2
    style Input fill:#f9f,stroke:#333,stroke-width:2px
    style D11 fill:#bbf,stroke:#333,stroke-width:2px,stroke-dasharray: 5 5
```

---

## � Legal & Compliance

**Dalion is explicitly Defensive-Only:**
- ✅ **No Offensive Actions**: No counter-hacking or external scanning.
- ✅ **Authorized Perimeter**: Only acts within your infrastructure.
- ✅ **Full Audit Trail**: Every decision is logged and traceable.
- ✅ **LGPD/GDPR**: Privacy by design, no PII extraction.

---

## 📚 Documentation
- [Installation Guide](./docs/01-install.md)
- [Architecture Axioms](./docs/00-overview.md)

---

**Built with CodeArk Framework**  
🏰 [codeark.com.br](https://codeark.com.br)

**The only SOC that predicts attacks before they happen.**
