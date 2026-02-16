# 🧭 Dalion

> **Multi-agent cybersecurity system with ML-powered threat detection and automated response.**

![Version](https://img.shields.io/badge/version-2.5.0-blue)
![License](https://img.shields.io/badge/license-Proprietary-red)
![Status](https://img.shields.io/badge/status-full--stack--operational-success)
![Coverage](https://img.shields.io/badge/agents-12%2F12-brightgreen)

---

## 🎯 What is Dalion?

**Dalion is a production-ready SOC (Security Operations Center) in software.** 

It deploys 9 specialized AI agents that work together to detect threats, predict attack vectors, and respond automatically—stopping damage before it occurs.

> **Validation Status:** Validated on **KC7 Module 1** (20 events) with **85%+ accuracy**. Suricata EVE integration active with calibrated severity escalation.

**Built for:**
- 🏥 **Healthcare** (LGPD/HIPAA compliance)
- 🏦 **Fintech** (Real-time fraud & anomaly detection)
- 🏢 **Enterprises** (Automated SOC scaling)
- 🇧🇷 **Brazilian Markets** (Native LGPD-first architecture)

---

## � Quick Start

### Prerequisites
- **Node.js** ≥ 18
- **Git**

### Installation
```bash
git clone https://github.com/yourorg/dalion.git
cd dalion
npm install
```

### Run Security Detection Demo
Validate the vertical analysis between Dalion Intelligence and Arqos Execution:
```bash
# Injects Dalion agents into the Arqos Engine
node tools/bridge_arqos.js

# Runs the vertical detection & orchestration demo
node tools/demo_vertical.js
```

### Configuration
Configure via `.env` file (see `.env.example`):
```ini
# Redis Cache (Recommended for Production)
CACHE_ENABLED=true
REDIS_URL=redis://localhost:6379

# API Keys
VT_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
```

**Expected output:**
```
✅ Sentinela: Detected 3 anomalies in SSH logs
✅ Strategos: Orchestrating response for 'Starter' tier
✅ Pipeline: Generated containment prompt for Firewall
```

---

## �️ Core Capabilities

### 12 Specialized Intelligence Agents (v2.5.0)

**Currently Implemented:**
- **D1 Infantaria (Dn-SEC-INF)** → First-line response (Rate limiting, IP blocks).
- **D2 Sentinela (Dn-SEC-SNT)** → Real-time anomaly & brute-force detection.
- **D3 Espionagem (Dn-SEC-ESP)** → APT detection & enrichment via 9 intel sources.
- **D4 IntelCampo (Dn-SEC-ICA)** → Tactical field intelligence analysis.
- **D5 Artilharia (Dn-SEC-ART)** → Compliance enforcement (LGPD/NIST) & Mutation Lab.
- **D6 Diplomacia (Dn-SEC-DIP)** → Executive Communication & Stakeholder Management.
- **D7 PsySec (Dn-SEC-PSY)** → Behavioral profiling and psychological analysis.
- **D8 ThreatIntel (Dn-SEC-THR)** → Threat intelligence aggregation and scoring.
- **D9 AttackGraph (Dn-SEC-GRA)** → Temporal attack graphs & predictive defense.
- **D10 Ethos (Dn-SEC-ETH)** → Intent classification (Legitimate vs. Malicious).
- **D11 AfterAction (Dn-SEC-AFT)** → Post-incident learning and feedback loop.
- **D12 Rottweiler (Dn-SEC-ROT)** → Strategic decision engine (Defensive-only).

> **Status:** Full Stack v2.5.0 implemented. 12/12 agents operational.

### Key Features
- ⚡ **Ultra-low Latency**: Core logic processing in < 1ms (In-memory benchmarks: ~27k EPS).
  > **Note on Real-world Performance:** Total end-to-end latency with I/O (JSON parsing, subprocesses) typically averages **200-500ms**.
- 🧠 **Predictive Defense**: Attack graph generation to stay ahead of adversaries.
- 🔒 **Sovereign Control**: Runs locally via Arqos Engine (LITE mode) for total data privacy.
- 📊 **Self-Refining**: AfterAction agent (Dn-SEC-AFT) learns from every incident.

---

### 🛰️ Suricata EVE Adapter (`tools/ingest_suricata_eve.ts`)
Dalion natively ingests **Suricata EVE JSON** logs, transforming raw network telemetry into actionable defense. This is not a simple wrapper; it's a full-cycle OODA integration.

- **High-Performance Ingestion:** Optimized streams with `highWaterMark` handling GBs of logs/day.
- **Closed-Loop System (D11):** Includes **Battle Damage Assessment (BDA)** to verify if blocks were successful and reinforce rules via Active Learning.
- **Deterministic & Auditable:** 
  - `--strict`: Fails pipeline if Critical alerts are allowed (Compliance Gate).
  - `--learn`: Enables persistent rule adjustment based on feedback.
  - `--limit`: Reproducible regression testing.

**Command:**
```bash
npx ts-node tools/ingest_suricata_eve.ts --tail /var/log/suricata/eve.json --strict --learn
```

**Recent Improvements (v2.5.0):**
- ✅ **D12 Suricata Bridge:** `event.severity` from Suricata alerts now directly influences D12 decisions.
  - `severity=1` (critical) → `ISOLATE_HOST`
  - `severity=2` (high) → `BLOCK`
  - `severity=3+` (medium/low) → Standard D12 logic
- ✅ **TypeScript Hardening:** Fixed compilation errors in `EnrichedIOC` type and optional array handling.
- ✅ **Real-world Validation:** Tested with testmynids.org GPL ATTACK_RESPONSE alerts (RCE simulation).


## 📦 Product Tiers & Repositories

Dalion está disponível em **3 tiers separados**, cada um com seu próprio repositório Git:

### 🌱 Community (Open Source)
**Repository:** [`Dalion_Community`](https://github.com/Scatlyus/Dalion_Community)

| Feature | Spec |
|---------|------|
| **Agentes** | 4 agentes (D1, D2, D10, D11) |
| **EPS Limit** | ∞ Ilimitado (soft warning 5K) |
| **Features Avançadas** | Nenhuma |
| **Threat Intel** | Básico (heurísticas locais) |
| **Attack Prediction** | ❌ |
| **Response Level** | Alert + Rate Limiting |
| **Suporte** | Community (GitHub Issues) |
| **Ideal para** | Labs, POCs, pequenas redes |

**Agentes Incluídos:**
- **D1 Infantaria** → First-line response
- **D2 Sentinela** → Anomaly detection
- **D10 Ethos** → Intent classification
- **D11 AfterAction** → Post-incident learning

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
