# 🛡️ D2 Sentinela (Real-World Implementation)

O D2 Sentinela é o motor de detecção em tempo real do Dalion VR01. Ele foi projetado para processar fluxos massivos de logs (KC7-standard) e identificar anomalias estruturais e comportamentais com latência ultra-baixa.

## 🚀 Performance & Robustez

Os benchmarks de guerra (executados em 13/02/2026) confirmam:
- **Throughput:** ~31.000 eventos por segundo por thread.
- **Latência:** Média de **0.03ms** por análise.
- **Memória:** < 8MB de overhead heap para janelas de 1.000 eventos.
- **Resiliência:** Validação de schema rigorosa (Zod) e tratamento automático de logs malformados.

## 🧠 Heurísticas Implementadas (8 Regras)

1. **Burst de Logins (`failed_logins_burst`):** Detecta 3+ falhas de login do mesmo IP em uma janela de 5 minutos.
2. **IoCs Conhecidos (`known_malicious_ioc`):** Matching em tempo real contra blacklists de IPs e Domínios (KC7/ThreatIntel).
3. **Comportamento Anômalo (`behavioral_deviation`):** Identifica logins em horários não-convencionais (ex: 3 AM).
4. **Atividade de Arquivo Suspeita (`unusual_file_activity`):** Monitora a criação de executáveis em pastas temporárias (`\Temp`, `\Public`).
5. **Termos Sensíveis (`sensitive_terms_in_message`):** Regex-matching para termos como `ransomware`, `exploit`, `shell`.
6. **Geo-Suspicious UA (`suspicious_geo_login`):** Identifica User-Agents de ferramentas de ataque (`curl`, `python-requests`, `nmap`).
7. **Unauthorized Access (`unauthorized_access_attempt`):** Monitora tentativas de acesso bloqueadas com severidade alta.
8. **High Severity Flag (`high_severity_event_flag`):** Reage instantaneamente a qualquer log já classificado como `CRITICAL` pela origem.

## 🧪 Estrutura de Testes

- **Unit Tests:** `npm test` (Suite Jest em `src/agents/d2_sentinela/__tests__`).
- **Performance:** `npx ts-node test_d2_performance.ts`.
- **Edge Cases:** `npx ts-node test_d2_edge_cases.ts`.

---
*Dalion VR01 - Omega Path Architecture*
