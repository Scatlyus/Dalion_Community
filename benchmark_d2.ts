import autocannon from 'autocannon';

async function runBenchmark() {
    console.log('🚀 Iniciando Autocannon Stress Test contra D2 Server...');

    const result = await autocannon({
        url: 'http://localhost:3000/api/analyze',
        connections: 100,
        duration: 10,
        method: 'POST',
        headers: {
            'content-type': 'application/json'
        },
        body: JSON.stringify({
            timestamp: new Date().toISOString(),
            event_id: 'benchmark',
            log_source_id: 'autocannon',
            source_ip: '1.2.3.4',
            action: 'login',
            status: 'failure',
            severity: 'medium',
            message: 'autocannon test with malware ransomware exploit terms'
        })
    });

    console.log('\n--- 📊 RESULTAODS DO AUTOCANNON ---');
    console.log(`Requests/sec: ${result.requests.average}`);
    console.log(`Latency Avg: ${result.latency.average} ms`);
    console.log(`Latency P99: ${result.latency.p99} ms`);
    console.log(`Total Requests: ${result.requests.total}`);
}

runBenchmark().catch(console.error);
