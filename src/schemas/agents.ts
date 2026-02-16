import { z } from 'zod';

const ipv4 = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/;

export const Kc7LogSchema = z.object({
    source: z.string(),
    timestamp: z.string().datetime(),
    sender: z.string().optional(),
    recipient: z.string().optional(),
    subject: z.string().optional(),
    link: z.string().url().optional(),
    source_ip: z.string().regex(ipv4, "Invalid IPv4").optional(),
    dest_ip: z.string().regex(ipv4, "Invalid IPv4").optional(),
    dest_port: z.number().optional(),
    bytes_sent: z.number().optional()
});

export const SentinelaDetectionSchema = z.object({
    agentId: z.literal('D2_SENTINELA'),
    timestamp: z.string().datetime(),
    anomaly_type: z.string(),
    severity: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
    confidence: z.number().min(0).max(1),
    entropy: z.number(),
    evidence: z.any()
});

export type Kc7Log = z.infer<typeof Kc7LogSchema>;
export type SentinelaDetection = z.infer<typeof SentinelaDetectionSchema>;
