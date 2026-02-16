# 🏗️ Dalion + Arqos: Implementation Guide

**Status:** Mock → Real Implementation  
**Timeline:** 4-6 semanas  
**Goal:** Sistema funcional com threat intel real

---

## 📋 Overview

**O que temos:**
- ✅ Specs completas (D1, D2, D3, D5, D11, D12)
- ✅ Demo scripts (mock)
- ✅ Estrutura Dalion
- ✅ Arqos Engine (a clonar)

**O que vamos construir:**
- 🎯 Agentes reais (não mock)
- 🎯 APIs integradas (VirusTotal, etc)
- 🎯 Bridge Dalion→Arqos
- 🎯 KC7 validation real
- 🎯 Production deployment

---

## 🎯 Fases de Implementação

### **Fase 0: Setup (1-2 dias)**

**Objetivo:** Arqos Engine rodando localmente

#### **Step 1: Clonar Arqos**

```bash
cd C:\root\Dalion
git clone https://github.com/Scatlyus/Arqos-Engine-FullStack.git arqos_engine
cd arqos_engine
```

#### **Step 2: Instalar Dependencies**

```bash
# Instalar Node packages
npm install

# Instalar Turbo (se não tiver)
npm install -g turbo
```

#### **Step 3: Configurar Environment**

```bash
# Copiar .env.example
cp .env.example .env

# Editar .env
# Adicionar:
# - Database URLs
# - API keys (se precisar)
```

#### **Step 4: Build & Run**

```bash
# Build todos os packages
turbo build

# Rodar em dev mode
turbo dev
```

#### **Step 5: Validar**

```bash
# Testar se API responde
curl http://localhost:3000/health

# Expected output:
# {"status":"ok","engine":"arqos"}
```

**✅ Checkpoint:** Se health check passou, Arqos está pronto.

---

### **Fase 1: Primeiro Agente Real (1 semana)**

**Objetivo:** D2 Sentinela funcional (não mock)

#### **Step 1: Estrutura**

```bash
cd C:\root\Dalion
mkdir -p src/agents/d2_sentinela
cd src/agents/d2_sentinela
```

**Criar arquivos:**
```
d2_sentinela/
├── index.ts           # Main entry
├── detector.ts        # Detection logic
├── schema.ts          # Input/output schemas
├── config.ts          # Configuration
└── __tests__/
    └── detector.test.ts
```

#### **Step 2: Implementar Schema**

```typescript
// src/agents/d2_sentinela/schema.ts
export interface SecurityEvent {
  timestamp: string;
  event_id: string;
  log_source_id: string;
  source_ip: string;
  destination_ip?: string;
  action: string;
  status: 'success' | 'failure' | 'blocked' | 'allowed';
  severity: 'informational' | 'low' | 'medium' | 'high' | 'critical';
  message: string;
  username?: string;
  // ... resto do schema da spec
}

export interface DetectionResult {
  anomaly: boolean;
  reason: string;
  anomaly_score: number; // 0-100
  risk_level: 'low' | 'medium' | 'high' | 'critical';
  tags: string[];
}
```

#### **Step 3: Implementar Detection Rules**

```typescript
// src/agents/d2_sentinela/detector.ts
import { SecurityEvent, DetectionResult } from './schema';

export class SentinelaDetector {
  
  /**
   * Analisa evento e retorna se é anômalo
   */
  async analyze(event: SecurityEvent): Promise<DetectionResult> {
    let score = 0;
    const tags: string[] = [];
    const reasons: string[] = [];

    // Rule 1: Failed logins burst
    if (this.isFailedLoginBurst(event)) {
      score += 70;
      tags.push('failed_login_burst');
      reasons.push('Multiple login failures detected');
    }

    // Rule 2: Suspicious geo login
    if (await this.isSuspiciousGeoLogin(event)) {
      score += 85;
      tags.push('suspicious_geo');
      reasons.push('Login from unusual location');
    }

    // Rule 3: Known malicious IoC
    if (await this.isKnownMalicious(event)) {
      score += 95;
      tags.push('known_malicious');
      reasons.push('Matches known threat indicators');
    }

    // ... mais rules

    // Calculate risk level
    const risk_level = this.calculateRiskLevel(score);
    
    return {
      anomaly: score >= 60, // Threshold
      reason: reasons.join('; '),
      anomaly_score: Math.min(score, 100),
      risk_level,
      tags
    };
  }

  private isFailedLoginBurst(event: SecurityEvent): boolean {
    // Implementação real (não mock!)
    return event.event_id === 'login_failure' && 
           event.status === 'failure';
  }

  private async isSuspiciousGeoLogin(event: SecurityEvent): Promise<boolean> {
    // TODO: Integrar com GeoIP database
    // Por enquanto: placeholder
    return false;
  }

  private async isKnownMalicious(event: SecurityEvent): Promise<boolean> {
    // TODO: Integrar com threat intel feeds
    // Por enquanto: placeholder
    return false;
  }

  private calculateRiskLevel(score: number): 'low' | 'medium' | 'high' | 'critical' {
    if (score >= 90) return 'critical';
    if (score >= 75) return 'high';
    if (score >= 60) return 'medium';
    return 'low';
  }
}
```

#### **Step 4: Testes Unitários**

```typescript
// src/agents/d2_sentinela/__tests__/detector.test.ts
import { SentinelaDetector } from '../detector';

describe('SentinelaDetector', () => {
  let detector: SentinelaDetector;

  beforeEach(() => {
    detector = new SentinelaDetector();
  });

  test('detecta failed login burst', async () => {
    const event = {
      timestamp: new Date().toISOString(),
      event_id: 'login_failure',
      log_source_id: 'windows_security',
      source_ip: '10.0.0.1',
      action: 'login',
      status: 'failure',
      severity: 'medium',
      message: 'Failed login attempt'
    };

    const result = await detector.analyze(event);
    
    expect(result.anomaly).toBe(true);
    expect(result.anomaly_score).toBeGreaterThan(60);
    expect(result.tags).toContain('failed_login_burst');
  });

  test('não detecta evento normal', async () => {
    const event = {
      timestamp: new Date().toISOString(),
      event_id: 'login_success',
      log_source_id: 'windows_security',
      source_ip: '10.0.0.1',
      action: 'login',
      status: 'success',
      severity: 'informational',
      message: 'Successful login'
    };

    const result = await detector.analyze(event);
    
    expect(result.anomaly).toBe(false);
    expect(result.anomaly_score).toBeLessThan(60);
  });
});
```

#### **Step 5: Rodar Testes**

```bash
npm test -- d2_sentinela
```

**✅ Checkpoint:** Testes passando = D2 funcional.

---

### **Fase 2: Bridge Dalion→Arqos (3-5 dias)**

**Objetivo:** Converter specs .md em axiomas Arqos

#### **Conceito do Bridge**

```
Dalion (formato produto):
├── packs/starter/agents/d2_sentinela.md
│   └── Markdown + YAML frontmatter
│
Bridge (tools/bridge_arqos.js)
│   └── Parser + Converter
│
Arqos (formato operacional):
└── arqos_engine/axioms/dalion_sentinela.yaml
    └── YAML com protocolo ATLAS
```

#### **Implementação**

Ver arquivo `tools/bridge_arqos.js` (próximo)

---

### **Fase 3: APIs Reais (2 semanas)**

**Objetivo:** Integrar VirusTotal, AbuseIPDB, etc

#### **D3 Espionagem - VirusTotal Integration**

```typescript
// src/agents/d3_espionagem/clients/virustotal.ts
export class VirusTotalClient {
  private apiKey: string;
  private baseUrl = 'https://www.virustotal.com/api/v3';

  constructor(apiKey: string) {
    this.apiKey = apiKey;
  }

  async getDomainReport(domain: string) {
    const response = await fetch(`${this.baseUrl}/domains/${domain}`, {
      headers: {
        'x-apikey': this.apiKey
      }
    });

    if (!response.ok) {
      throw new Error(`VT API error: ${response.status}`);
    }

    const data = await response.json();
    
    return {
      reputation: this.calculateReputation(data),
      malicious_votes: data.data.attributes.last_analysis_stats.malicious,
      categories: data.data.attributes.categories,
      last_analysis_date: data.data.attributes.last_analysis_date
    };
  }

  private calculateReputation(data: any): number {
    const stats = data.data.attributes.last_analysis_stats;
    const total = stats.malicious + stats.suspicious + stats.undetected + stats.harmless;
    const bad = stats.malicious + (stats.suspicious * 0.5);
    
    // Normalize to -1 (malicious) to +1 (clean)
    return 1 - (2 * bad / total);
  }
}
```

#### **Environment Variables**

```bash
# .env
VT_API_KEY=your_virustotal_key
ABUSEIPDB_API_KEY=your_abuseipdb_key
```

**Como conseguir keys:**
1. VirusTotal: https://www.virustotal.com/gui/join-us (free tier: 4 req/min)
2. AbuseIPDB: https://www.abuseipdb.com/api (free tier: 1000 req/day)

---

### **Fase 4: KC7 Real (1 semana)**

**Objetivo:** Validar com dataset KC7 real

#### **Step 1: Baixar Dataset KC7**

```bash
# Download oficial do KC7
curl -O https://kc7cyber.com/datasets/phishing_intrusion.zip
unzip phishing_intrusion.zip -d data/kc7/
```

#### **Step 2: Converter KC7 → Sentinela Schema**

```typescript
// tools/kc7_converter.ts
import * as fs from 'fs';

function convertKC7toSentinela(kc7Log: any): SecurityEvent {
  return {
    timestamp: kc7Log.EventTime,
    event_id: kc7Log.EventID,
    log_source_id: kc7Log.Computer,
    source_ip: kc7Log.IpAddress,
    action: kc7Log.LogonType === 'Network' ? 'login' : 'unknown',
    status: kc7Log.Status === '0x0' ? 'success' : 'failure',
    severity: determineSeverity(kc7Log),
    message: kc7Log.Message
  };
}
```

#### **Step 3: Processar Dataset**

```typescript
// tools/kc7_validation_real.ts
import { SentinelaDetector } from '../src/agents/d2_sentinela/detector';
import { convertKC7toSentinela } from './kc7_converter';

async function processKC7Dataset() {
  const kc7Data = JSON.parse(fs.readFileSync('data/kc7/phishing.json', 'utf8'));
  const detector = new SentinelaDetector();

  let detected = 0;
  let falsePositives = 0;

  for (const log of kc7Data.logs) {
    const event = convertKC7toSentinela(log);
    const result = await detector.analyze(event);

    if (result.anomaly) {
      detected++;
      
      // Validar com ground truth do KC7
      if (log.is_malicious !== true) {
        falsePositives++;
      }
    }
  }

  console.log(`Detected: ${detected}/${kc7Data.logs.length}`);
  console.log(`False Positive Rate: ${(falsePositives / detected * 100).toFixed(2)}%`);
}
```

---

## 📊 Timeline Realista

```
Semana 1: Setup + D2 Sentinela MVP
├── Dias 1-2: Arqos Engine rodando
├── Dias 3-4: D2 schema + basic detection
└── Dias 5-7: D2 testes + refinamento

Semana 2: D2 Production-Ready
├── Dias 8-10: Todas as 8 detection rules
├── Dias 11-12: Testes extensivos
└── Dias 13-14: Performance optimization

Semana 3: D3 Espionagem
├── Dias 15-17: VT + AbuseIPDB integration
├── Dias 18-19: Conflict resolution
└── Dias 20-21: Caching + rate limiting

Semana 4: Bridge + Integration
├── Dias 22-24: Bridge Dalion→Arqos
├── Dias 25-26: Integração D2 + D3
└── Dias 27-28: kc7_validation_real.ts

Semana 5: D12 Rottweiler
├── Dias 29-31: Decision engine
├── Dias 32-33: Firewall integration mock
└── Dias 34-35: Audit trail

Semana 6: Polish + Deploy
├── Dias 36-38: Bug fixes
├── Dias 39-40: Documentation
└── Dias 41-42: Production deploy
```

**Total: 6 semanas (42 dias úteis)**

---

## ✅ Checkpoints de Validação

### **Week 1 Checkpoint:**
- [ ] Arqos Engine roda localmente
- [ ] D2 Sentinela detecta 1 tipo de anomalia
- [ ] Testes unitários passam

### **Week 2 Checkpoint:**
- [ ] D2 implementa 8 detection rules
- [ ] False positive rate < 5%
- [ ] Performance: < 50ms por evento

### **Week 3 Checkpoint:**
- [ ] VirusTotal API funciona
- [ ] Retorna reputation real
- [ ] Rate limiting implementado

### **Week 4 Checkpoint:**
- [ ] Bridge converte 1 spec .md
- [ ] Arqos carrega axioma gerado
- [ ] D2 + D3 integrados funcionam

### **Week 5 Checkpoint:**
- [ ] Rottweiler toma decisões
- [ ] Audit trail gerado
- [ ] Fluxo completo funciona

### **Week 6 Checkpoint:**
- [ ] KC7 dataset processado
- [ ] Métricas reais geradas
- [ ] Sistema deployável

---

## 🚨 Riscos & Mitigação

### **Risco 1: APIs externas com rate limit**

**Problema:** VT free = 4 req/min

**Solução:**
```typescript
// Implementar caching
const cache = new Map();

async function getVTReputationCached(domain: string) {
  if (cache.has(domain)) {
    return cache.get(domain);
  }
  
  const result = await vtClient.getDomainReport(domain);
  cache.set(domain, result);
  return result;
}
```

---

### **Risco 2: Arqos Engine complexo**

**Problema:** Curva de aprendizado

**Solução:**
1. Começar com 1 agente simples (D2)
2. Estudar exemplos existentes no Arqos
3. Pedir ajuda no Discord/Issues

---

### **Risco 3: Timeline otimista**

**Problema:** 6 semanas pode ser apertado

**Solução:**
- Priorizar D2 + D3 (core)
- D12 pode ser simplificado (mock firewall)
- Outros agentes (D1, D4-D11) ficam pra fase 2

---

## 🎯 Entregáveis Finais

**Ao final das 6 semanas, você terá:**

1. **Código Real:**
   - ✅ D2 Sentinela funcional
   - ✅ D3 Espionagem com APIs reais
   - ✅ D12 Rottweiler (decision engine)

2. **Integração:**
   - ✅ Bridge Dalion→Arqos
   - ✅ Agentes carregam no Arqos
   - ✅ Maestro UI mostra detecções

3. **Validação:**
   - ✅ KC7 dataset processado
   - ✅ Métricas reais (detection rate, FP rate)
   - ✅ Case study documentado

4. **Deploy:**
   - ✅ Docker Compose setup
   - ✅ Environment variables
   - ✅ Production-ready

---

## 📚 Próximos Passos

**Hoje/Amanhã:**
1. Clonar Arqos Engine
2. Rodar health check
3. Criar estrutura src/agents/d2_sentinela/

**Esta Semana:**
1. Implementar D2 schema
2. Implementar 2-3 detection rules
3. Testes unitários

**Próxima Semana:**
1. Completar D2 (8 rules)
2. Começar D3 (VT integration)

---

**Pronto pra começar? 🚀**

**Próximo arquivo:** `src/agents/d2_sentinela/index.ts`
