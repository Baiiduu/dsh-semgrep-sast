// Adapted from dsh-semgrep-sast 0.3.0 (MIT); see scripts/sync-core.mjs.
const SEVERITY_ORDER = {
    error: 0,
    warning: 1,
    info: 2
};
function compareFindings(left, right) {
    return SEVERITY_ORDER[left.severity] - SEVERITY_ORDER[right.severity] || left.path.localeCompare(right.path) || left.startLine - right.startLine || left.startColumn - right.startColumn || left.ruleId.localeCompare(right.ruleId);
}
function relevance(finding, focus) {
    const tags = normalizeCwe(finding.metadata?.cwe) ?? [];
    if (tags.some((tag)=>focus.includes(tag))) return 0;
    const related = {
        'CWE-20': [
            'CWE-400',
            'CWE-770',
            'CWE-1333',
            'CWE-835'
        ],
        'CWE-22': [
            'CWE-36',
            'CWE-23',
            'CWE-73'
        ],
        'CWE-36': [
            'CWE-22',
            'CWE-23',
            'CWE-73'
        ],
        'CWE-400': [
            'CWE-770',
            'CWE-1333',
            'CWE-835',
            'CWE-789'
        ],
        'CWE-770': [
            'CWE-400',
            'CWE-789'
        ]
    };
    return focus.some((cwe)=>tags.some((tag)=>related[cwe]?.includes(tag))) ? 1 : 2;
}
export function selectFindings(findings, maxFindings, options = {}) {
    const focus = options.focusCwes ?? [];
    if (focus.some((cwe)=>!/^CWE-[1-9][0-9]*$/.test(cwe))) {
        throw new Error('semgrep-sast: focus_cwes must contain canonical CWE identifiers');
    }
    const tier = (finding)=>focus.length === 0 ? 0 : relevance(finding, focus);
    const sorted = [
        ...findings
    ].sort((a, b)=>tier(a) - tier(b) || compareFindings(a, b));
    if (!options.diversify) return sorted.slice(0, maxFindings);
    const output = [];
    for (const priority of [
        0,
        1,
        2
    ]){
        const files = new Map();
        for (const finding of sorted.filter((item)=>tier(item) === priority)){
            const queue = files.get(finding.path) ?? [];
            queue.push(finding);
            files.set(finding.path, queue);
        }
        while(files.size > 0 && output.length < maxFindings){
            for (const [path, queue] of files){
                output.push(queue.shift());
                if (queue.length === 0) files.delete(path);
                if (output.length === maxFindings) break;
            }
        }
    }
    return output;
}
function normalizeCwe(values) {
    if (values === undefined) return undefined;
    const normalized = values.flatMap((value)=>{
        const match = /\bCWE-[1-9][0-9]*\b/i.exec(value);
        return match === null ? [] : [
            match[0].toUpperCase()
        ];
    });
    const uniqueValues = [
        ...new Set(normalized)
    ];
    return uniqueValues.length === 0 ? undefined : uniqueValues;
}
function normalizeOwasp(values) {
    if (values === undefined) return undefined;
    const normalized = values.flatMap((value)=>{
        const match = /\bA[0-9]{1,2}:[0-9]{4}\b/i.exec(value);
        return match === null ? [] : [
            match[0].toUpperCase()
        ];
    });
    const uniqueValues = [
        ...new Set(normalized)
    ];
    return uniqueValues.length === 0 ? undefined : uniqueValues;
}
function normalizeReferences(values) {
    if (values === undefined) return undefined;
    const normalized = values.filter((value)=>{
        try {
            const url = new URL(value);
            return url.protocol === 'https:' || url.protocol === 'http:';
        } catch  {
            return false;
        }
    });
    const uniqueValues = [
        ...new Set(normalized)
    ];
    return uniqueValues.length === 0 ? undefined : uniqueValues;
}
function createRule(finding) {
    const cwe = normalizeCwe(finding.metadata?.cwe);
    const owasp = normalizeOwasp(finding.metadata?.owasp);
    const references = normalizeReferences(finding.metadata?.references);
    return {
        id: finding.ruleId,
        severity: finding.severity,
        ...cwe === undefined ? {} : {
            cwe
        },
        ...owasp === undefined ? {} : {
            owasp
        },
        ...references === undefined ? {} : {
            references
        }
    };
}
function createEvidence(finding) {
    const evidence = [];
    if (finding.matchedCode !== undefined) {
        evidence.push({
            type: 'semgrep.matched-code',
            data: {
                text: finding.matchedCode
            }
        });
    }
    if (finding.metavariables !== undefined) {
        evidence.push({
            type: 'semgrep.metavariables',
            data: {
                ...finding.metavariables
            }
        });
    }
    return evidence;
}
function createFindingId(finding) {
    return [
        'semgrep',
        encodeURIComponent(finding.ruleId),
        encodeURIComponent(finding.path),
        String(finding.startLine),
        String(finding.startColumn),
        String(finding.endLine),
        String(finding.endColumn)
    ].join(':');
}
function createFinding(finding) {
    return {
        id: createFindingId(finding),
        scanner: 'semgrep',
        rule: createRule(finding),
        message: finding.message,
        location: {
            path: finding.path,
            startLine: finding.startLine,
            startColumn: finding.startColumn,
            endLine: finding.endLine,
            endColumn: finding.endColumn
        },
        ...finding.fingerprint === undefined ? {} : {
            fingerprint: finding.fingerprint
        },
        evidence: createEvidence(finding)
    };
}
function createDiagnostic(diagnostic) {
    return {
        level: diagnostic.level === 'warn' ? 'warning' : diagnostic.level,
        type: diagnostic.type,
        message: diagnostic.message?.trim() || `Semgrep diagnostic code ${diagnostic.code}`,
        code: diagnostic.code
    };
}
export function createSemgrepSastResult(scan, configuration, maxFindings, options = {}) {
    if (!Number.isInteger(maxFindings) || maxFindings < 1) {
        throw new Error('semgrep-sast: maxFindings must be a positive integer');
    }
    const selectedFindings = selectFindings(scan.findings, maxFindings, options).map(createFinding);
    return {
        schemaVersion: "ssc-sast/v1",
        status: scan.status,
        scanner: {
            name: 'semgrep',
            version: scan.version,
            configuration
        },
        scannedPaths: [
            ...scan.scannedPaths
        ],
        findings: selectedFindings,
        diagnostics: scan.diagnostics.map(createDiagnostic),
        summary: {
            totalFindings: scan.findings.length,
            returnedFindings: selectedFindings.length,
            truncated: selectedFindings.length < scan.findings.length,
            durationMs: scan.durationMs
        }
    };
}
