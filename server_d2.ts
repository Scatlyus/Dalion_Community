import express from 'express';
import { DalionSentinela } from './src/agents/d2_sentinela/index';

const app = express();
const port = 3000;
const sentinela = new DalionSentinela();

app.use(express.json());

app.post('/api/analyze', async (req, res) => {
    try {
        const result = await sentinela.analyze(req.body);
        res.json(result);
    } catch (error: any) {
        res.status(400).json({ error: error.message });
    }
});

app.listen(port, () => {
    console.log(`🛡️ Dalion D2 Server running at http://localhost:${port}`);
});
