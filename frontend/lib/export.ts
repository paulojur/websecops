import { jsPDF } from 'jspdf';
import autoTable from 'jspdf-autotable';

type TechnologyInfo = {
    version?: string;
    category?: string;
};

type Remediation = {
    title: string;
    severity: string;
    confidence: string;
    confidence_reason?: string;
    category: string;
    root_cause?: string;
    evidence: string;
    evidence_items?: Array<{ source: string; detail: string }>;
    why_it_matters: string;
    recommendation: string;
    next_step?: string;
    snippets?: { nginx?: string; apache?: string };
    report_sections?: {
        risk: string;
        evidence: string;
        impact: string;
        recommendation: string;
        next_step: string;
    };
    report_text: string;
};

type Correlation = {
    cve_id: string;
    description: string;
    correlation_reason?: string;
    remediation?: Remediation;
};

type TargetDetailsData = {
    target: {
        url: string;
        created_at?: string;
        technologies?: Record<string, TechnologyInfo | string>;
    };
    correlations: Correlation[];
    hardening?: Remediation[];
    summary?: {
        total: number;
        analyst_note?: string;
        severity_counts?: Record<string, number>;
        risk_groups?: Array<{ root_cause: string; count: number; highest_severity: string; next_step: string }>;
        top_risks: Array<{ id: string; severity: string; score?: number; confidence?: string; reason: string; next_step?: string }>;
    };
};

type ScanAlert = {
    alert: string;
    risk: string;
    confidence?: string;
    description?: string;
    method?: string;
    url?: string;
    sourceid?: string;
    remediations?: AlertRemediation[];
};

type AlertRemediation = {
    title: string;
    category: string;
    confidence: string;
    confidence_reason?: string;
    root_cause?: string;
    evidence: string;
    recommendation: string;
    next_step?: string;
    report_text: string;
    report_sections?: {
        risk: string;
        evidence: string;
        impact: string;
        recommendation: string;
        next_step: string;
    };
    snippets?: { nginx?: string; apache?: string };
};

type CoverageItem = {
    name: string;
    status: 'pass' | 'fail';
    cwe?: string;
};

type ScanTriage = {
    total_alerts: number;
    analyst_note?: string;
    risk_groups?: Array<{ root_cause: string; count: number; highest_severity: string; next_step: string }>;
};

export function downloadBlob(blob: Blob, filename: string) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

export function escapeCSV(value: string): string {
    const str = String(value ?? '');
    if (str.includes(',') || str.includes(';') || str.includes('"') || str.includes('\n')) {
        return `"${str.replace(/"/g, '""')}"`;
    }
    return str;
}

export function addCSVRow(rows: string[], ...cells: string[]) {
    rows.push(cells.map((c) => escapeCSV(c)).join(','));
}

export function exportTargetCorrelationsCSV(data: TargetDetailsData) {
    const rows: string[] = [];
    rows.push(['CVE', 'Severidade', 'Confianca', 'Descricao', 'Motivo da Correlacao', 'Recomendacao', 'Proximo Passo'].map(escapeCSV).join(','));

    for (const corr of data.correlations) {
        addCSVRow(
            rows,
            corr.cve_id,
            corr.remediation?.severity ?? '',
            corr.remediation?.confidence ?? '',
            corr.description.replace(/\n/g, ' '),
            corr.correlation_reason ?? '',
            corr.remediation?.recommendation.replace(/\n/g, ' ') ?? '',
            corr.remediation?.next_step ?? '',
        );
    }

    const content = '\uFEFF' + rows.join('\n');
    downloadBlob(new Blob([content], { type: 'text/csv;charset=utf-8;' }), `correlacoes_${data.target.url.replace(/[^a-z0-9]/gi, '_')}.csv`);
}

export function exportScanResultsCSV(results: ScanAlert[], triage: ScanTriage) {
    const rows: string[] = [];
    rows.push(['Alerta', 'Severidade', 'Confianca', 'Fonte', 'URL', 'Metodo', 'Descricao', 'Evidencia', 'Recomendacao', 'Proximo Passo'].map(escapeCSV).join(','));

    for (const alert of (results ?? [])) {
        const remediation = alert.remediations?.[0];
        addCSVRow(
            rows,
            alert.alert,
            alert.risk,
            alert.confidence ?? '',
            alert.sourceid ?? '',
            alert.url ?? '',
            alert.method ?? '',
            (alert.description ?? '').replace(/\n/g, ' '),
            (remediation?.evidence ?? '').replace(/\n/g, ' '),
            (remediation?.recommendation ?? '').replace(/\n/g, ' '),
            remediation?.next_step ?? '',
        );
    }

    const content = '\uFEFF' + rows.join('\n');
    downloadBlob(new Blob([content], { type: 'text/csv;charset=utf-8;' }), 'scan_results.csv');
}

export function exportTargetCorrelationsPDF(data: TargetDetailsData) {
    const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
    const pageWidth = doc.internal.pageSize.getWidth();
    const margin = 14;
    const maxLineWidth = pageWidth - margin * 2;
    let y = margin;

    doc.setFontSize(18);
    doc.setTextColor(0, 0, 0);
    doc.text('Relatorio de Correlacoes de CVE', pageWidth / 2, y, { align: 'center' });
    y += 8;

    doc.setFontSize(11);
    doc.setTextColor(60, 60, 60);
    doc.text(`Alvo: ${data.target.url}`, margin, y);
    y += 5;
    const createdAt = data.target.created_at ? new Date(data.target.created_at).toLocaleString('pt-BR') : 'N/A';
    doc.text(`Adicionado em: ${createdAt}`, margin, y);
    y += 5;
    if (data.summary) {
        doc.text(`Total de riscos: ${data.summary.total}`, margin, y);
        y += 5;
    }

    const techs = Object.entries(data.target.technologies ?? {});
    if (techs.length > 0) {
        doc.setFontSize(10);
        doc.setTextColor(40, 40, 40);
        doc.text('Tecnologias detectadas:', margin, y);
        y += 4;
        doc.setFontSize(9);
        doc.setTextColor(80, 80, 80);
        for (const [key, val] of techs) {
            const display = typeof val === 'object' && val !== null
                ? [val.version, val.category].filter(Boolean).join(' - ')
                : String(val ?? 'Sem detalhes');
            const line = `- ${key}: ${display}`;
            const lines = doc.splitTextIntoSize(line, maxLineWidth);
            doc.text(lines, margin, y);
            y += lines.length * 4;
        }
        y += 3;
    }

    if (y > 260) { doc.addPage(); y = margin; }

    doc.setFontSize(14);
    doc.setTextColor(0, 0, 0);
    doc.text('Riscos Priorizados', margin, y);
    y += 6;

    if (data.summary?.top_risks?.length) {
        doc.setFontSize(10);
        for (const risk of data.summary.top_risks) {
            if (y > 260) { doc.addPage(); y = margin; }
            const riskLine = `${risk.id} | ${risk.severity} ${risk.score ? `(CVSS ${risk.score})` : ''}`;
            doc.setFont('helvetica', 'bold');
            doc.text(riskLine, margin, y);
            y += 4;
            doc.setFont('helvetica', 'normal');
            doc.setTextColor(80, 80, 80);
            const reasonLines = doc.splitTextIntoSize(risk.reason, maxLineWidth);
            doc.text(reasonLines, margin + 2, y);
            y += reasonLines.length * 4 + 2;
            doc.setTextColor(0, 0, 0);
        }
        y += 3;
    }

    if (data.correlations.length === 0) {
        if (y > 260) { doc.addPage(); y = margin; }
        doc.setFontSize(10);
        doc.setTextColor(100, 100, 100);
        doc.text('Nenhuma CVE recente encontrada.', margin, y);
    } else {
        doc.setFontSize(14);
        doc.setTextColor(0, 0, 0);
        doc.text('Detalhamento de CVEs', margin, y);
        y += 6;

        for (let i = 0; i < data.correlations.length; i++) {
            const corr = data.correlations[i];
            if (y > 250) { doc.addPage(); y = margin; }

            doc.setFontSize(12);
            doc.setFont('helvetica', 'bold');
            doc.text(corr.cve_id, margin, y);
            y += 5;

            doc.setFont('helvetica', 'normal');
            doc.setFontSize(9);
            doc.setTextColor(60, 60, 60);
            if (corr.correlation_reason) {
                doc.text(`Motivo: ${corr.correlation_reason}`, margin, y);
                y += 4;
            }

            const descLines = doc.splitTextIntoSize(corr.description, maxLineWidth);
            doc.text(descLines, margin, y);
            y += descLines.length * 3.5 + 2;

            if (corr.remediation) {
                doc.setFontSize(10);
                doc.setTextColor(0, 0, 0);
                doc.setFont('helvetica', 'bold');
                doc.text('Correcao sugerida:', margin, y);
                y += 4;
                doc.setFont('helvetica', 'normal');
                doc.setFontSize(9);
                doc.setTextColor(60, 60, 60);
                const recLines = doc.splitTextIntoSize(corr.remediation.recommendation, maxLineWidth);
                doc.text(recLines, margin, y);
                y += recLines.length * 3.5 + 1;
                doc.text(`Confianca: ${corr.remediation.confidence}`, margin, y);
                y += 4;
                if (corr.remediation.next_step) {
                    const nextLines = doc.splitTextIntoSize(`Proximo passo: ${corr.remediation.next_step}`, maxLineWidth);
                    doc.text(nextLines, margin, y);
                    y += nextLines.length * 3.5 + 2;
                }
                if (corr.remediation.report_text) {
                    doc.setTextColor(80, 80, 80);
                    const reportLines = doc.splitTextIntoSize(corr.remediation.report_text, maxLineWidth);
                    doc.text(reportLines, margin, y);
                    y += reportLines.length * 3 + 3;
                }
            }

            doc.setTextColor(0, 0, 0);
            if (i < data.correlations.length - 1) {
                doc.setDrawColor(200, 200, 200);
                doc.line(margin, y, pageWidth - margin, y);
                y += 4;
            }
        }
    }

    if (data.hardening && data.hardening.length > 0) {
        if (y > 250) { doc.addPage(); y = margin; }
        doc.setFontSize(14);
        doc.setTextColor(0, 0, 0);
        doc.text('Hardening Recomendado', margin, y);
        y += 6;
        for (const item of data.hardening) {
            if (y > 250) { doc.addPage(); y = margin; }
            doc.setFontSize(10);
            doc.setFont('helvetica', 'bold');
            doc.text(`${item.title} [${item.category} | ${item.confidence}]`, margin, y);
            y += 4;
            doc.setFont('helvetica', 'normal');
            doc.setFontSize(9);
            doc.setTextColor(80, 80, 80);
            const recLines = doc.splitTextIntoSize(item.recommendation, maxLineWidth);
            doc.text(recLines, margin, y);
            y += recLines.length * 3.5 + 3;
            doc.setTextColor(0, 0, 0);
        }
    }

    doc.save(`relatorio_correlacoes_${data.target.url.replace(/[^a-z0-9]/gi, '_')}.pdf`);
}

export function exportScanResultsPDF(results: ScanAlert[], triage: ScanTriage, coverage: CoverageItem[] = []) {
    const doc = new jsPDF({ orientation: 'landscape', unit: 'mm', format: 'a4' });
    const pageWidth = doc.internal.pageSize.getWidth();
    const margin = 14;
    let y = margin;

    doc.setFontSize(18);
    doc.setTextColor(0, 0, 0);
    doc.text('Relatorio de Resultados de Scan', pageWidth / 2, y, { align: 'center' });
    y += 8;

    doc.setFontSize(11);
    doc.setTextColor(60, 60, 60);
    doc.text(`Total de alertas: ${triage.total_alerts}`, margin, y);
    y += 6;

    const triageGroups = triage.risk_groups ?? [];
    if (triageGroups.length > 0) {
        doc.setTextColor(0, 0, 0);
        doc.setFontSize(10);
        doc.setFont('helvetica', 'bold');
        doc.text('Grupos de Risco:', margin, y);
        y += 4;
        doc.setFont('helvetica', 'normal');
        doc.setFontSize(9);
        doc.setTextColor(80, 80, 80);
        for (const group of triageGroups) {
            const line = `- ${group.root_cause}: ${group.count} alertas (${group.highest_severity})`;
            doc.text(line, margin, y);
            y += 4;
        }
        y += 3;
    }

    if (results && results.length > 0) {
        doc.setFontSize(14);
        doc.setTextColor(0, 0, 0);
        doc.text('Detalhamento de Alertas', margin, y);
        y += 4;

        const tableBody = results.map((alert) => {
            const rem = alert.remediations?.[0];
            return [
                alert.alert,
                alert.risk,
                alert.confidence ?? '',
                alert.sourceid === 'static_analysis' ? 'Estatica' : 'Dinamica (ZAP)',
                (alert.description ?? '').slice(0, 120) + ((alert.description?.length ?? 0) > 120 ? '...' : ''),
                (rem?.recommendation ?? '').slice(0, 150) + ((rem?.recommendation?.length ?? 0) > 150 ? '...' : ''),
            ];
        });

        const tableColumnStyles = {
            4: { cellWidth: 60 },
            5: { cellWidth: 80 },
        };

        autoTable(doc, {
            startY: y,
            head: [['Alerta', 'Severidade', 'Confianca', 'Fonte', 'Descricao', 'Recomendacao']],
            body: tableBody,
            theme: 'grid',
            headStyles: { fontSize: 9, cellPadding: 2 },
            bodyStyles: { fontSize: 8, cellPadding: 2 },
            margin: { left: margin, right: margin },
            columnStyles: tableColumnStyles,
            styles: { overflow: 'linebreak' },
        });

        y = doc.lastAutoTable?.finalY ?? y;
        if (y > 180) { doc.addPage(); y = margin; }

        if (results.some((a) => (a.remediations?.length ?? 0) > 0)) {
            doc.setFontSize(14);
            doc.setTextColor(0, 0, 0);
            doc.text('Remediacoes', margin, y);
            y += 5;

            for (const alert of results.filter((a) => (a.remediations?.length ?? 0) > 0)) {
                for (const rem of alert.remediations ?? []) {
                    if (y > 270) { doc.addPage(); y = margin; }
                    doc.setFontSize(10);
                    doc.setFont('helvetica', 'bold');
                    doc.text(`${alert.alert} - ${rem.title}`, margin, y);
                    y += 4;
                    doc.setFont('helvetica', 'normal');
                    doc.setFontSize(9);
                    doc.setTextColor(80, 80, 80);
                    const lines = doc.splitTextIntoSize(`${rem.recommendation} | Confianca: ${rem.confidence} | ${rem.evidence}`, pageWidth - margin * 2);
                    doc.text(lines, margin, y);
                    y += lines.length * 3.5 + 3;
                    doc.setTextColor(0, 0, 0);
                }
            }
        }
    }

    if (coverage.length > 0) {
        if (y > 250) { doc.addPage(); y = margin; }
        doc.setFontSize(14);
        doc.setTextColor(0, 0, 0);
        doc.text('Relatorio de Cobertura', margin, y);
        y += 4;

        const coverageBody = coverage.map((item) => [item.name, item.status === 'pass' ? 'PASS' : 'FAIL', item.cwe ? `CWE-${item.cwe}` : '-']);
        autoTable(doc, {
            startY: y,
            head: [['Teste', 'Status', 'CWE']],
            body: coverageBody,
            theme: 'grid',
            headStyles: { fontSize: 9, cellPadding: 2 },
            bodyStyles: { fontSize: 9, cellPadding: 2 },
            margin: { left: margin, right: margin },
            styles: { overflow: 'linebreak' },
        });
    }

    doc.save('scan_results.pdf');
}
