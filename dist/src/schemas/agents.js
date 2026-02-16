"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SentinelaDetectionSchema = exports.Kc7LogSchema = void 0;
const zod_1 = require("zod");
const ipv4 = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/;
exports.Kc7LogSchema = zod_1.z.object({
    source: zod_1.z.string(),
    timestamp: zod_1.z.string().datetime(),
    sender: zod_1.z.string().optional(),
    recipient: zod_1.z.string().optional(),
    subject: zod_1.z.string().optional(),
    link: zod_1.z.string().url().optional(),
    source_ip: zod_1.z.string().regex(ipv4, "Invalid IPv4").optional(),
    dest_ip: zod_1.z.string().regex(ipv4, "Invalid IPv4").optional(),
    dest_port: zod_1.z.number().optional(),
    bytes_sent: zod_1.z.number().optional()
});
exports.SentinelaDetectionSchema = zod_1.z.object({
    agentId: zod_1.z.literal('D2_SENTINELA'),
    timestamp: zod_1.z.string().datetime(),
    anomaly_type: zod_1.z.string(),
    severity: zod_1.z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
    confidence: zod_1.z.number().min(0).max(1),
    entropy: zod_1.z.number(),
    evidence: zod_1.z.any()
});
