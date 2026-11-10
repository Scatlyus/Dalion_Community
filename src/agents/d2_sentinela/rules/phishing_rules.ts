import { DetectionRule } from '../types';

/**
 * Phishing and social engineering detection rules
 */
export function getPhishingRules(): Map<string, DetectionRule> {
    const rules = new Map<string, DetectionRule>();

    // Rule 16: Shortened URL Detection
    rules.set('shortened_url', {
        name: 'shortened_url',
        description: 'URL redirector service detected (T1566)',
        impact_score: 40,
        check: async (event) => {
            const context = (event as any).context || {};
            const url = (context.url || '').toLowerCase();
            const domain = (context.domain || '').toLowerCase();
            const services = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'buff.ly'];
            return services.some(s => {
                const isExact = domain === s;
                const isSubdomain = domain.endsWith('.' + s);
                const isUrlStart = url.includes('://' + s + '/') || url.startsWith(s + '/');
                return isExact || isSubdomain || isUrlStart;
            });
        }
    });

    // Rule 17: Phishing Keywords
    rules.set('phishing_keywords', {
        name: 'phishing_keywords',
        description: 'Sensitive phishing terms in URL/Domain',
        impact_score: 50,
        check: async (event) => {
            const context = (event as any).context || {};
            const target = (context.url || context.domain || '').toLowerCase();
            const keywords = ['verify', 'login', 'invoice', 'update', 'secure', 'account', 'banking'];
            return keywords.some(k => target.includes(k));
        }
    });

    // Rule 18: Suspicious Download (EXE)
    rules.set('suspicious_download_exe', {
        name: 'suspicious_download_exe',
        description: 'Potential malicious binary download (.exe)',
        impact_score: 60,
        check: async (event) => {
            const context = (event as any).context || {};
            const url = (context.url || '').toLowerCase();
            const file = (context.file_path || '').toLowerCase();
            return url.endsWith('.exe') || file.endsWith('.exe');
        }
    });

    // Rule 19: Binary Download (Octet-Stream)
    rules.set('binary_download_octet_stream', {
        name: 'binary_download_octet_stream',
        description: 'Download with application/octet-stream content type',
        impact_score: 40,
        check: async (event) => {
            const context = (event as any).context || {};
            return context.content_type === 'application/octet-stream';
        }
    });

    return rules;
}
