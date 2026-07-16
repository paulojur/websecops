export type AppMode = 'live' | 'demo';

export type DemoTechInfo = {
    version?: string;
    category?: string;
};

export type DemoRemediation = {
    title: string;
    severity: string;
    confidence: string;
    confidence_reason?: string;
    category: string;
    root_cause?: string;
    evidence: string;
    evidence_items?: Array<{
        source: string;
        detail: string;
    }>;
    why_it_matters: string;
    recommendation: string;
    next_step?: string;
    snippets?: {
        nginx?: string;
        apache?: string;
    };
    report_sections?: {
        risk: string;
        evidence: string;
        impact: string;
        recommendation: string;
        next_step: string;
    };
    report_text: string;
};

export type DemoCorrelation = {
    cve_id: string;
    description: string;
    score: number;
    severity: string;
    published: string;
    matched_keyword: string;
    correlation_reason: string;
    confidence: string;
    confidence_reason: string;
    remediation: DemoRemediation;
};

export type DemoRiskGroup = {
    root_cause: string;
    count: number;
    highest_severity: string;
    next_step: string;
};

export type DemoSummaryItem = {
    id: string;
    severity: string;
    score?: number;
    confidence?: string;
    reason: string;
    next_step?: string;
};

export type DemoTarget = {
    id: number;
    url: string;
    technologies: Record<string, DemoTechInfo>;
    subdomains: string[];
    vuln_status: string;
    last_scan: string;
    created_at: string;
    potential_vulns: number;
    correlations: DemoCorrelation[];
    summary: {
        total: number;
        analyst_note: string;
        severity_counts: Record<string, number>;
        risk_groups: DemoRiskGroup[];
        top_risks: DemoSummaryItem[];
    };
    hardening: DemoRemediation[];
};

const MODE_KEY = 'websecops.mode';
const TARGETS_KEY = 'websecops.demo.targets';

const DEFAULT_TARGETS: Array<Pick<DemoTarget, 'url'>> = [
    { url: 'https://portal.acme.test' },
    { url: 'https://api.payments.test' },
    { url: 'https://blog.wordpress.test' },
];

function isBrowser() {
    return typeof window !== 'undefined';
}

function normalizeUrl(rawUrl: string) {
    const trimmed = (rawUrl || '').trim();
    if (!trimmed) {
        throw new Error('URL is required');
    }

    const value = trimmed.includes('://') ? trimmed : `https://${trimmed}`;
    const parsed = new URL(value);
    return parsed.toString().replace(/\/$/, '');
}

function slugify(value: string) {
    return value
        .toLowerCase()
        .replace(/https?:\/\//g, '')
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-+|-+$/g, '')
        .slice(0, 24) || 'target';
}

function inferTechnologies(url: string): Record<string, DemoTechInfo> {
    const parsed = new URL(url);
    const footprint = `${parsed.hostname} ${parsed.pathname}`.toLowerCase();

    if (footprint.includes('wordpress') || footprint.includes('wp-') || footprint.includes('/wp')) {
        return {
            WordPress: { version: '6.4.3', category: 'CMS' },
            PHP: { version: '8.1', category: 'Runtime' },
            Nginx: { version: '1.24', category: 'Web Server' },
        } satisfies Record<string, DemoTechInfo>;
    }

    if (footprint.includes('api') || footprint.includes('gateway') || footprint.includes('service')) {
        return {
            FastAPI: { version: '0.110', category: 'Framework' },
            PostgreSQL: { version: '16', category: 'Database' },
            Redis: { version: '7', category: 'Cache' },
        } satisfies Record<string, DemoTechInfo>;
    }

    if (footprint.includes('shop') || footprint.includes('store') || footprint.includes('commerce')) {
        return {
            'Next.js': { version: '14.2', category: 'Frontend' },
            React: { version: '18.3', category: 'Frontend' },
            'Node.js': { version: '20', category: 'Runtime' },
        } satisfies Record<string, DemoTechInfo>;
    }

    return {
        Nginx: { version: '1.24', category: 'Web Server' },
        'Next.js': { version: '14.2', category: 'Frontend' },
        PostgreSQL: { version: '16', category: 'Database' },
    } satisfies Record<string, DemoTechInfo>;
}

function buildRemediation(title: string, techName: string, severity: string, confidence: string, version?: string): DemoRemediation {
    return {
        title,
        severity,
        confidence,
        confidence_reason: version
            ? 'A versao foi inferida do inventario local e deve ser validada antes de virar incidente confirmado.'
            : 'A correlacao veio apenas do nome da tecnologia, sem versao confirmada.',
        category: 'CVE',
        root_cause: 'Componente potencialmente vulneravel',
        evidence: `Tecnologia detectada: ${techName}${version ? ` ${version}` : ''}`,
        why_it_matters: 'A versao conhecida reduz o ruido da triagem e acelera a tomada de decisao.',
        recommendation: `Atualize ${techName} para uma versao suportada e valide o comportamento apos o patch.`,
        next_step: 'Confirme a versao real no ambiente antes de abrir o caso como confirmado.',
        snippets: {
            nginx: 'add_header X-Content-Type-Options "nosniff" always;',
            apache: 'Header always set X-Content-Type-Options "nosniff"',
        },
        report_sections: {
            risk: title,
            evidence: `Tecnologia detectada: ${techName}${version ? ` ${version}` : ''}`,
            impact: 'Uma superficie exposta com versao conhecida precisa ser priorizada e revisada.',
            recommendation: `Atualize ${techName} e documente a validacao da versao corrigida.`,
            next_step: 'Executar nova deteccao depois da correcao para reduzir falso positivo.',
        },
        report_text: `${title}. Evidencia: Tecnologia detectada: ${techName}${version ? ` ${version}` : ''}. Recomendacao: atualize o componente e valide a versao corrigida.`,
    };
}

function buildCorrelations(technologies: Record<string, DemoTechInfo>, url: string): DemoCorrelation[] {
    const current = new Date().toISOString();
    const correlations: DemoCorrelation[] = [];

    Object.entries(technologies).forEach(([techName, techInfo], index) => {
        const hasVersion = Boolean(techInfo.version);
        const severity = hasVersion ? 'HIGH' : 'MEDIUM';
        const confidence = hasVersion ? 'MEDIUM' : 'LOW';
        const score = hasVersion ? 8.1 : 6.4;
        const cveId = `DEMO-${slugify(techName).toUpperCase()}-${index + 1}`;
        const keyword = hasVersion ? `${techName} ${techInfo.version}` : techName;

        correlations.push({
            cve_id: cveId,
            description: `Exemplo demonstrativo de correlacao entre ${techName} e um achado priorizado para ${url}.`,
            score,
            severity,
            published: current,
            matched_keyword: keyword,
            correlation_reason: hasVersion
                ? `Correlacao por tecnologia e versao detectadas em '${keyword}'.`
                : `Correlacao por nome da tecnologia em '${keyword}'.`,
            confidence,
            confidence_reason: hasVersion
                ? 'Nome + versao reduzem o ruido na correlacao local.'
                : 'Nao ha versao confirmada; trate como hipotese ate validar o inventario.',
            remediation: buildRemediation(
                `Atualizar ${techName}`,
                techName,
                severity,
                confidence,
                techInfo.version,
            ),
        });
    });

    return correlations;
}

function buildSummary(correlations: DemoCorrelation[]): DemoTarget['summary'] {
    const severityCounts: Record<string, number> = {};
    correlations.forEach((item) => {
        severityCounts[item.severity] = (severityCounts[item.severity] || 0) + 1;
    });

    const riskGroupsMap = new Map<string, DemoRiskGroup>();
    correlations.forEach((item) => {
        const rootCause = item.remediation.root_cause || item.remediation.category;
        const existing = riskGroupsMap.get(rootCause) || {
            root_cause: rootCause,
            count: 0,
            highest_severity: 'INFO',
            next_step: item.remediation.next_step || 'Revisar evidencias antes de priorizar.',
        };

        existing.count += 1;
        existing.highest_severity = severityRank(item.severity) > severityRank(existing.highest_severity)
            ? item.severity
            : existing.highest_severity;
        riskGroupsMap.set(rootCause, existing);
    });

    const sorted = [...correlations].sort((a, b) => severityRank(b.severity) - severityRank(a.severity));

    return {
        total: correlations.length,
        analyst_note: correlations.length === 0
            ? 'Nenhum achado foi correlacionado agora. Isso reduz ruido, mas nao substitui revisao manual.'
            : 'Comece pelos itens de maior severidade e maior confianca para acelerar a triagem.',
        severity_counts: severityCounts,
        risk_groups: [...riskGroupsMap.values()],
        top_risks: sorted.slice(0, 5).map((item) => ({
            id: item.cve_id,
            severity: item.severity,
            score: item.score,
            confidence: item.confidence,
            reason: item.correlation_reason,
            next_step: item.remediation.next_step,
        })),
    };
}

function buildHardening(): DemoRemediation[] {
    return [
        {
            title: 'Aplicar baseline de headers de seguranca',
            severity: 'INFO',
            confidence: 'MEDIUM',
            confidence_reason: 'E uma recomendacao preventiva e precisa ser validada contra os fluxos reais da aplicacao.',
            category: 'Hardening',
            root_cause: 'Baseline defensivo ainda nao padronizado',
            evidence: 'Recomendacao preventiva para aplicacoes web expostas.',
            why_it_matters: 'Headers consistentes reduzem superficie de ataque e melhoram a postura de navegacao.',
            recommendation: 'Padronize CSP, HSTS, X-Content-Type-Options, Referrer-Policy e Permissions-Policy.',
            next_step: 'Aplicar primeiro em homologacao e validar login, embeds e integracoes externas.',
            snippets: {
                nginx: 'add_header Content-Security-Policy "frame-ancestors \'self\';" always;',
                apache: 'Header always set Content-Security-Policy "frame-ancestors \'self\';"',
            },
            report_sections: {
                risk: 'Aplicar baseline de headers de seguranca',
                evidence: 'Recomendacao preventiva para aplicacoes web expostas.',
                impact: 'Headers consistentes reduzem superficie de ataque e melhoram a postura de navegacao.',
                recommendation: 'Padronize CSP, HSTS, X-Content-Type-Options, Referrer-Policy e Permissions-Policy.',
                next_step: 'Aplicar primeiro em homologacao e validar login, embeds e integracoes externas.',
            },
            report_text: 'Aplicar baseline de headers de seguranca para reduzir superficie de ataque e padronizar a navegacao.',
        },
    ];
}

function severityRank(severity: string) {
    switch ((severity || '').toUpperCase()) {
        case 'CRITICAL': return 4;
        case 'HIGH': return 3;
        case 'MEDIUM': return 2;
        case 'LOW': return 1;
        default: return 0;
    }
}

function buildTargetRecord(url: string): DemoTarget {
    const normalizedUrl = normalizeUrl(url);
    const technologies = inferTechnologies(normalizedUrl);
    const correlations = buildCorrelations(technologies, normalizedUrl);

    return {
        id: Date.now(),
        url: normalizedUrl,
        technologies,
        subdomains: [],
        vuln_status: correlations.length > 0 ? 'VULNERABLE' : 'SECURE',
        last_scan: new Date().toISOString(),
        created_at: new Date().toISOString(),
        potential_vulns: correlations.length,
        correlations,
        summary: buildSummary(correlations),
        hardening: buildHardening(),
    };
}

function loadTargets(): DemoTarget[] {
    if (!isBrowser()) {
        return [];
    }

    const stored = window.localStorage.getItem(TARGETS_KEY);
    if (stored) {
        try {
            return JSON.parse(stored) as DemoTarget[];
        } catch {
            window.localStorage.removeItem(TARGETS_KEY);
        }
    }

    const seeded = DEFAULT_TARGETS.map((item) => buildTargetRecord(item.url));
    window.localStorage.setItem(TARGETS_KEY, JSON.stringify(seeded));
    return seeded;
}

function saveTargets(targets: DemoTarget[]) {
    if (!isBrowser()) {
        return;
    }

    window.localStorage.setItem(TARGETS_KEY, JSON.stringify(targets));
}

export function getAppMode(): AppMode {
    if (!isBrowser()) {
        return 'live';
    }

    return window.localStorage.getItem(MODE_KEY) === 'demo' ? 'demo' : 'live';
}

export function setAppMode(mode: AppMode) {
    if (!isBrowser()) {
        return;
    }

    window.localStorage.setItem(MODE_KEY, mode);
    if (mode === 'demo') {
        loadTargets();
    }
}

export function getDemoTargets() {
    return loadTargets();
}

export function getDemoTarget(id: number) {
    return loadTargets().find((target) => target.id === id) || null;
}

export function upsertDemoTarget(url: string) {
    const targets = loadTargets();
    const normalizedUrl = normalizeUrl(url);
    const existingIndex = targets.findIndex((target) => target.url === normalizedUrl);
    const created = buildTargetRecord(normalizedUrl);

    if (existingIndex >= 0) {
        created.id = targets[existingIndex].id;
        targets[existingIndex] = created;
    } else {
        targets.unshift(created);
    }

    saveTargets(targets);
    return created;
}

export function deleteDemoTarget(id: number) {
    const targets = loadTargets().filter((target) => target.id !== id);
    saveTargets(targets);
}

export function ensureDemoTargets() {
    if (!isBrowser()) {
        return [] as DemoTarget[];
    }

    return loadTargets();
}
