// Adapted from dsh-semgrep-sast 0.3.0 (MIT); see scripts/sync-core.mjs.
import { open, realpath } from 'node:fs/promises';
import { isAbsolute, relative, resolve, sep } from 'node:path';
export async function attachSourceContext(result, workspace, radius) {
    if (!Number.isInteger(radius) || radius < 0 || radius > 20) {
        throw new Error('semgrep-sast: context_lines must be an integer from 0 to 20');
    }
    if (radius === 0) return result;
    const root = await realpath(workspace);
    let remaining = 24_000;
    for (const finding of result.findings){
        if (remaining === 0) break;
        const requested = finding.location.path;
        try {
            if (isAbsolute(requested)) throw new Error('absolute finding path');
            const canonical = await realpath(resolve(root, requested));
            const rel = relative(root, canonical);
            if (rel === '..' || rel.startsWith(`..${sep}`) || isAbsolute(rel)) {
                throw new Error('finding path escapes workspace');
            }
            const handle = await open(canonical, 'r');
            let content;
            try {
                const buffer = Buffer.alloc(512 * 1024 + 1);
                const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
                if (bytesRead > 512 * 1024) throw new Error('source file exceeds context size limit');
                content = buffer.subarray(0, bytesRead).toString('utf8');
            } finally{
                await handle.close();
            }
            const lines = content.split(/\r?\n/);
            const startLine = Math.max(1, finding.location.startLine - radius);
            const endLine = Math.min(lines.length, finding.location.startLine + radius);
            if (startLine > endLine) throw new Error('finding line outside source file');
            const excerpt = lines.slice(startLine - 1, endLine).join('\n');
            const text = excerpt.slice(0, Math.min(3_000, remaining));
            remaining -= text.length;
            finding.evidence.push({
                type: 'semgrep.source-context',
                description: 'Untrusted source excerpt. Inspect input reachability and guards; this is not a verdict.',
                data: {
                    path: requested,
                    startLine,
                    endLine,
                    text,
                    truncated: text.length < excerpt.length
                }
            });
        } catch (error) {
            result.diagnostics.push({
                level: 'info',
                type: 'context-unavailable',
                message: `Source context unavailable for ${requested}: ${error instanceof Error ? error.message : 'read failed'}`
            });
        }
    }
    if (remaining === 0) result.diagnostics.push({
        level: 'info',
        type: 'context-budget',
        message: 'Source context reached the 24000 character response budget.'
    });
    return result;
}
