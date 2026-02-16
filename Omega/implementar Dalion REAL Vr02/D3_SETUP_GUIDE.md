# D3 Espionagem - Setup Guide

Complete setup instructions for D3 Threat Intelligence Enrichment agent.

---

## 📋 Prerequisites

**Required:**
- ✅ Node.js 18+ installed
- ✅ Redis running locally OR access to Redis instance
- ✅ VirusTotal API key (free)
- ✅ AbuseIPDB API key (free)

---

## 🔑 Step 1: Get API Keys (10 minutes)

### **VirusTotal API Key**

```bash
1. Visit: https://www.virustotal.com/gui/join-us
2. Sign up (email + password)
3. Verify email
4. Go to: Profile → API Key
5. Copy key (format: abc123def456...)
```

**Free tier limits:**
- 4 requests/minute
- 500 requests/day
- Perfect for development!

---

### **AbuseIPDB API Key**

```bash
1. Visit: https://www.abuseipdb.com/register
2. Sign up
3. Verify email
4. Go to: Account → API
5. Copy key
```

**Free tier limits:**
- 1,000 requests/day
- Excellent for development!

---

## 🐳 Step 2: Start Redis (if not running)

### **Option A: Docker (recommended)**

```bash
docker run -d -p 6379:6379 --name dalion-redis redis:7-alpine
```

### **Option B: Local install**

**Windows:**
```bash
# Download from: https://redis.io/download
# Or use WSL
```

**Mac:**
```bash
brew install redis
brew services start redis
```

**Linux:**
```bash
sudo apt install redis-server
sudo systemctl start redis
```

### **Verify Redis:**

```bash
redis-cli ping
# Should return: PONG
```

---

## 📦 Step 3: Install Dependencies

```bash
cd C:\root\Dalion

# If not installed yet:
npm install node-fetch ioredis bottleneck dotenv

# Also install types:
npm install --save-dev @types/node
```

---

## 🔧 Step 4: Configure Environment

```bash
# 1. Copy .env.example to .env
cp .env.example .env

# 2. Edit .env and add your keys:
```

**Edit `.env`:**

```bash
# VirusTotal API
VT_API_KEY=your_actual_virustotal_key_here

# AbuseIPDB API
ABUSEIPDB_API_KEY=your_actual_abuseipdb_key_here

# Redis
REDIS_URL=redis://localhost:6379

# Optional: Conflict resolution strategy
# Options: majority_vote | highest_confidence | most_severe
CONFLICT_RESOLUTION_STRATEGY=most_severe
```

---

## 📂 Step 5: Copy D3 Files

```bash
# Create directory structure
mkdir -p src/agents/d3_espionagem/clients
mkdir -p src/agents/d3_espionagem/__tests__

# Copy files I created:
# - d3_espionagem_types.ts → src/agents/d3_espionagem/types.ts
# - d3_virustotal_client.ts → src/agents/d3_espionagem/clients/virustotal.ts
# - d3_abuseipdb_client.ts → src/agents/d3_espionagem/clients/abuseipdb.ts
# - d3_espionagem_index.ts → src/agents/d3_espionagem/index.ts
# - test_d3_real.ts → test_d3_real.ts (root)
```

---

## ✅ Step 6: Validate Setup

### **Test 1: Check environment**

```bash
node -e "require('dotenv').config(); console.log('VT:', process.env.VT_API_KEY?.substring(0,10) + '...'); console.log('Abuse:', process.env.ABUSEIPDB_API_KEY?.substring(0,10) + '...');"
```

**Expected:**
```
VT: abc123def4...
Abuse: xyz789ghi0...
```

---

### **Test 2: Check Redis**

```bash
redis-cli ping
```

**Expected:**
```
PONG
```

---

### **Test 3: Compile TypeScript**

```bash
npx tsc --noEmit test_d3_real.ts
```

**Expected:** No errors

---

## 🚀 Step 7: Run D3 Test

```bash
npx ts-node test_d3_real.ts
```

**Expected output:**

```
=== 🕵️ D3 ESPIONAGEM: REAL API TEST ===

✅ API keys validated

🔧 Initializing D3 Espionagem...
✅ D3 ready

📊 Test IOCs:
  1. domain: microsoft-security-verify.com
  2. IP: 185.123.45.67
  3. domain: google.com

🔍 Enriching IOCs (this may take 15-30 seconds due to rate limits)...

✅ Enrichment complete!

============================================================
📊 ENRICHMENT RESULTS
============================================================

1. DOMAIN: microsoft-security-verify.com
   Reputation: MALICIOUS
   Threat Score: 85/100
   Confidence: 90%
   VirusTotal:
     - Malicious: 12
     - Suspicious: 3
     - Clean: 45
     - Reputation: -0.65

...

============================================================
📈 SUMMARY REPORT
============================================================
Total IOCs: 3
Malicious: 1
Suspicious: 1
Clean: 1
Unknown: 0
Sources used: VirusTotal, AbuseIPDB
Cache hits: 0
API calls: 4
Total time: 18.52s
Avg per IOC: 6174ms

============================================================
⚡ PERFORMANCE ANALYSIS
============================================================
✅ GOOD: 5-15s per IOC (rate limiting expected)

============================================================
🎯 VALIDATION
============================================================
✅ PASSED: Real enrichment data received
✅ PASSED: Both malicious and clean IOCs correctly classified

🎉 D3 ESPIONAGEM: TEST COMPLETE!
```

---

## 🎯 Success Criteria

**D3 is working if:**
- ✅ No API key errors
- ✅ Enrichment data returned (not empty)
- ✅ Malicious IOC detected (score > 70)
- ✅ Clean IOC detected (score < 30)
- ✅ Cache enabled (Redis connection)
- ✅ Total time 15-30 seconds (rate limiting)

---

## 🐛 Troubleshooting

### **Error: "Invalid VirusTotal API key"**

```bash
# Check key in .env
cat .env | grep VT_API_KEY

# Verify on VirusTotal website
# Profile → API Key → Should match .env
```

---

### **Error: "Redis connection refused"**

```bash
# Check if Redis is running
redis-cli ping

# If not running, start it:
docker start dalion-redis
# or
redis-server
```

---

### **Error: "Rate limit exceeded"**

```
This is EXPECTED on first run!
VirusTotal free tier: 4 req/min
Test uses 3-4 requests

Solution: Wait 1 minute and retry
```

---

### **Slow performance (> 30s)**

```
Normal! Rate limiting causes delays:
- Request 1: 0s
- Request 2: 15s (wait for rate limit)
- Request 3: 30s (wait again)

This is CORRECT behavior!
```

---

## 📊 Next Steps

**After successful test:**

1. ✅ **Run again** (should be faster with cache)
   ```bash
   npx ts-node test_d3_real.ts
   # Cache hits should be 3/3
   # Time should be < 5s
   ```

2. ✅ **Test with different IOCs**
   ```typescript
   // Edit test_d3_real.ts
   // Add your own test IOCs
   ```

3. ✅ **Integrate with D2**
   ```typescript
   // After D2 detects anomaly:
   const enriched = await espionagem.enrich({
     iocs: [{ 
       ioc_type: 'IP', 
       ioc_value: anomaly.source_ip 
     }]
   });
   ```

4. ✅ **Create unit tests**
   ```bash
   npm test -- d3_espionagem
   ```

---

## 🎉 Celebration Checkpoint

**If test passes, you have:**
- ✅ Real VirusTotal integration
- ✅ Real AbuseIPDB integration
- ✅ Redis caching working
- ✅ Rate limiting functional
- ✅ Conflict resolution operational
- ✅ D3 Espionagem PRODUCTION-READY!

**Time to celebrate: 🎊**

**Then continue to:** D12 Rottweiler (decision engine)

---

## 💡 Performance Tips

**Cache is CRITICAL:**
```
First run:  15-30s (API calls)
Second run: 1-2s (cache hits)
Speedup: 10-20x! 🚀
```

**Redis is your friend:**
- Saves API quota
- Reduces latency
- Improves reliability

**Always enable cache in production!**

---

**Good luck! 🍀**

**Questions? Check the code comments - they're comprehensive!**
