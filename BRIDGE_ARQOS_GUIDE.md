# Bridge Arqos V2 - Usage Guide

Complete guide for converting Dalion specs to Arqos axioms.

---

## 🎯 What It Does

**Converts:**
```
packs/starter/agents/d2_sentinela.md (Dalion spec)
↓
arqos_engine/axioms/dalion_d2_sentinela.yaml (Arqos axiom)
```

**Features:**
- ✅ Parses Markdown + YAML frontmatter
- ✅ Maps cognitive tiers (T0-T4)
- ✅ Assigns governance levels
- ✅ Detects implementations
- ✅ Validates schemas
- ✅ Generates Arqos-compatible YAML

---

## 📋 Prerequisites

1. ✅ Arqos Engine cloned
2. ✅ Dalion packs/ structure
3. ✅ js-yaml installed

```bash
# Clone Arqos if not done
cd C:\root\Dalion
git clone https://github.com/Scatlyus/Arqos-Engine-FullStack.git arqos_engine

# Install js-yaml if needed
npm install js-yaml
```

---

## 🚀 Usage

### **Basic (all agents, all tiers):**

```bash
node tools/bridge_arqos_v2.js
```

### **Single agent:**

```bash
node tools/bridge_arqos_v2.js --agent=d2_sentinela
```

### **Single tier:**

```bash
node tools/bridge_arqos_v2.js --tier=starter
```

### **Validate only (no files created):**

```bash
node tools/bridge_arqos_v2.js --validate-only
```

### **Combine options:**

```bash
node tools/bridge_arqos_v2.js --tier=starter --agent=d2
```

---

## 📊 Expected Output

```
🌉 Dalion → Arqos Bridge V2
Converting agent specs to axioms...

📦 Processing tier: starter
  ✅ d2_sentinela → dalion_d2_sentinela.yaml ✅ (with impl)
  ✅ d6_diplomacia → dalion_d6_diplomacia.yaml ⚠️  (placeholder)
  ✅ d10_ethos → dalion_d10_ethos.yaml ⚠️  (placeholder)

📦 Processing tier: pro
  ✅ d1_infantaria → dalion_d1_infantaria.yaml ⚠️  (placeholder)
  ✅ d3_espionagem → dalion_d3_espionagem.yaml ✅ (with impl)
  ...

======================================================================
📊 Bridge Summary
======================================================================
Processed:           12
Success:             12
Failed:              0
With implementation: 2
Placeholder:         10

By Cognitive Tier:
  T0: 1
  T1: 2
  T2: 4
  T3: 3
  T4: 2

By Governance Level:
  low: 4
  medium: 4
  high: 4
======================================================================

✅ Axioms generated successfully!
📂 Location: arqos_engine/packages/engine/src/core/axioms

⚠️  10 axiom(s) created without implementation
   These will use placeholder handlers until code is available
```

---

## 🎯 What Gets Created

### **File Structure:**

```
arqos_engine/packages/engine/src/core/axioms/
├── dalion_d2_sentinela.yaml     ✅ (with impl)
├── dalion_d3_espionagem.yaml    ✅ (with impl)
├── dalion_d1_infantaria.yaml    ⚠️  (placeholder)
├── dalion_d4_intel_campo.yaml   ⚠️  (placeholder)
├── dalion_d5_artilharia.yaml    ⚠️  (placeholder)
├── dalion_d6_diplomacia.yaml    ⚠️  (placeholder)
├── dalion_d7_psysec.yaml        ⚠️  (placeholder)
├── dalion_d8_threatintel.yaml   ⚠️  (placeholder)
├── dalion_d9_attackgraph.yaml   ⚠️  (placeholder)
├── dalion_d10_ethos.yaml        ⚠️  (placeholder)
├── dalion_d11_afteraction.yaml  ⚠️  (placeholder)
└── dalion_d12_rottweiler.yaml   ⚠️  (placeholder)
```

---

## 📄 Axiom Example

**Input (d2_sentinela.md):**

```markdown
---
name: Dalion Sentinela
version: 1.4.4
description: Real-time security event detector
subcategory: threat_detection
timeout: 30000
memory_enabled: true
---

# D2 Sentinela

Real-time detection agent with 8 heuristic rules.
```

**Output (dalion_d2_sentinela.yaml):**

```yaml
id: dalion_d2_sentinela
version: 1.4.4
name: Dalion Sentinela
description: Real-time security event detector
author: Dalion Team
category: security
subcategory: threat_detection
tier: starter
deployment_profile: development

handler:
  type: typescript
  entry: src/agents/d2_sentinela/index.ts
  timeout_ms: 30000
  max_retries: 3

atlas:
  cognitive_tier: T0
  governance_level: low
  memory_enabled: true
  learning_enabled: false
  autonomy_level: supervised

observability:
  logging:
    enabled: true
    level: info
    structured: true
  metrics:
    enabled: true
    prometheus: true
  tracing:
    enabled: false
    sample_rate: 0.1

error_handling:
  strategy: retry_with_backoff
  max_retries: 3
  retry_delay_ms: 1000
  fallback: log_and_continue

performance:
  max_concurrent: 10
  queue_size: 1000
  rate_limit:
    requests: 100
    window_ms: 60000

security:
  authentication_required: false
  authorization_required: false
  audit_trail: true
  data_encryption: false
```

---

## 🏷️ Cognitive Tier Mapping

**Auto-detected based on agent name:**

| Agent | Tier | Function |
|-------|------|----------|
| D2 Sentinela | T0 | Detection & Monitoring |
| D1 Infantaria | T1 | Response & Containment |
| D12 Rottweiler | T1 | Response & Containment |
| D3 Espionagem | T2 | Enrichment & Classification |
| D5 Artilharia | T2 | Enrichment & Classification |
| D8 ThreatIntel | T2 | Enrichment & Classification |
| D10 Ethos | T2 | Enrichment & Classification |
| D4 Intel Campo | T3 | Analysis & Prediction |
| D7 PsySec | T3 | Analysis & Prediction |
| D9 AttackGraph | T3 | Analysis & Prediction |
| D6 Diplomacia | T4 | Learning & Governance |
| D11 AfterAction | T4 | Learning & Governance |

---

## 🛡️ Governance Level Assignment

**Auto-assigned based on criticality:**

**High (requires approval):**
- D12 Rottweiler (containment)
- D11 AfterAction (ML learning)
- D5 Artilharia (compliance)
- D1 Infantaria (fast response)

**Medium (supervised):**
- D3 Espionagem (enrichment)
- D10 Ethos (classification)
- D9 AttackGraph (prediction)

**Low (autonomous):**
- D2 Sentinela (monitoring)
- D6 Diplomacia (reporting)
- Others

---

## ⚠️ Implementation Detection

**Bridge checks these locations:**

```
src/agents/d2_sentinela/index.ts
src/agents/d2_sentinela/index.js
src/agents/d2-sentinela/index.ts
```

**If found:** `handler.type = "typescript"`  
**If not found:** `handler.type = "placeholder"`

**Placeholders use fallback:**
- Log event
- Return empty result
- Don't crash Arqos

---

## ✅ Validation Rules

**Bridge validates:**

1. ✅ YAML frontmatter present
2. ✅ Required fields: name, version
3. ✅ Cognitive tier: T0-T4
4. ✅ Governance level: low/medium/high
5. ✅ Handler defined
6. ✅ ATLAS protocol fields

**On error:**
- ❌ Shows validation errors
- ❌ Skips file (doesn't create axiom)
- ❌ Continues with other agents

---

## 🔧 Troubleshooting

### **Error: "Arqos axioms directory not found"**

```bash
# Solution:
cd C:\root\Dalion
git clone https://github.com/Scatlyus/Arqos-Engine-FullStack.git arqos_engine
```

---

### **Error: "No YAML frontmatter found"**

```markdown
# Fix spec file - must start with:
---
name: Agent Name
version: 1.0.0
---

# Content here
```

---

### **Warning: "created without implementation"**

```
Normal! Means:
- Axiom created ✅
- But no src/agents/X/index.ts found
- Will use placeholder handler

Action: Implement agent code later
```

---

## 🎯 Next Steps After Bridge

**1. Verify axioms created:**

```bash
ls arqos_engine/packages/engine/src/core/axioms/dalion_*.yaml
# Should show 12 files
```

**2. Load in Arqos:**

```bash
cd arqos_engine
npm run dev

# Axioms auto-load on start
```

**3. Test orchestration:**

```typescript
// In Arqos, trigger D2:
const result = await arqos.execute('dalion_d2_sentinela', {
  timestamp: new Date().toISOString(),
  event_id: 'test',
  // ... event data
});
```

**4. Verify logs:**

```bash
# Check Arqos logs:
tail -f arqos_engine/logs/engine.log

# Should see:
[INFO] Loaded axiom: dalion_d2_sentinela
[INFO] Loaded axiom: dalion_d3_espionagem
```

---

## 📊 Success Criteria

**Bridge succeeded if:**

- ✅ 12 YAML files created
- ✅ No validation errors
- ✅ 2+ with implementation (D2, D3)
- ✅ Cognitive tiers assigned
- ✅ Governance levels set
- ✅ Arqos can load axioms

---

## 💡 Tips

**Fast iteration:**

```bash
# 1. Update spec
vim packs/starter/agents/d2_sentinela.md

# 2. Re-bridge (single agent)
node tools/bridge_arqos_v2.js --agent=d2_sentinela

# 3. Restart Arqos
cd arqos_engine && npm run dev
```

**Validate before bridging:**

```bash
# Check all specs valid:
node tools/bridge_arqos_v2.js --validate-only

# If errors, fix specs first
```

**Check what has implementation:**

```bash
# Bridge shows:
✅ (with impl)  → Code exists
⚠️  (placeholder) → Code missing
```

---

## 🎉 Expected Result

**After successful bridge:**

```
Dalion agents (12 specs)
↓ [Bridge V2]
↓
Arqos axioms (12 YAMLs)
↓ [Arqos Engine]
↓
Orchestrated system ✅

D2 → Detects
D3 → Enriches
D1 → Responds
D12 → Contains

DALION INTEGRATED! 🎊
```

---

**Ready to bridge?** 🌉

```bash
node tools/bridge_arqos_v2.js
```

**Good luck!** 🍀
