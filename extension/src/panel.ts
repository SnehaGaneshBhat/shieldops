import * as vscode from 'vscode';
import * as crypto from 'crypto';
import type { Category, Evidence, Explanation, Report, ReportItem } from './types';

const META: Record<Category, { label: string; tone: string }> = {
  KNOWN_MALICIOUS_ADVISORY: { label: 'Malicious advisory', tone: 'critical' },
  KNOWN_VULNERABILITY: { label: 'Known vulnerability', tone: 'high' },
  BUILD_MISMATCH: { label: 'Build mismatch', tone: 'high' },
  COMPILER_ANOMALY: { label: 'Compiler anomaly', tone: 'violet' },
  SUSPICIOUS_INDICATOR: { label: 'Suspicious indicator', tone: 'amber' },
  UNRESOLVED: { label: 'Unresolved check', tone: 'slate' },
  NO_KNOWN_ISSUES: { label: 'No known issues detected', tone: 'green' }
};
const ORDER = Object.keys(META) as Category[];
const esc = (value: unknown): string => String(value ?? '')
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;').replace(/'/g, '&#39;');

let panel: vscode.WebviewPanel | undefined;

export function showReport(report: Report): void {
  if (!panel) {
    panel = vscode.window.createWebviewPanel(
      'buildguardReport', 'BuildGuard · Scan report', vscode.ViewColumn.Beside,
      { enableScripts: true }
    );
    panel.onDidDispose(() => { panel = undefined; });
    panel.webview.onDidReceiveMessage((message) => {
      if (message?.type === 'export') void vscode.commands.executeCommand('buildguard.exportHtml');
    });
  }
  panel.webview.html = render(report, false);
  panel.reveal(vscode.ViewColumn.Beside, true);
}

export function renderStandaloneReport(report: Report): string {
  return render(report, true);
}

function getExplanation(item: ReportItem): Explanation {
  const nested = item.explanation;
  if (nested && typeof nested === 'object' && !Array.isArray(nested)) return nested;
  return {
    plain_explanation: item.plain_explanation,
    why_it_matters: item.why_it_matters,
    recommended_actions: item.recommended_actions,
    limitations: item.limitations
  };
}

function evidenceList(item: ReportItem): Evidence[] {
  return Array.isArray(item.evidence)
    ? item.evidence.filter((entry): entry is Evidence => Boolean(entry) && typeof entry === 'object')
    : [];
}

function isSimulation(item: ReportItem): boolean {
  return item.simulated === true || evidenceList(item).some((entry) =>
    entry.data?.simulation === true || entry.data?.simulated_compromise === true
  );
}

function card(item: ReportItem, reportSource?: string): string {
  const explanation = getExplanation(item);
  const evidence = evidenceList(item).map((entry) => ({
    type: entry.type,
    rule_id: entry.rule_id,
    data: entry.data,
    untrusted_text: entry.untrusted_text
  }));
  const actions = Array.isArray(explanation.recommended_actions)
    ? explanation.recommended_actions.map((action) => `<li>${esc(action)}</li>`).join('')
    : '';
  const sourceType = item.explanation_source ?? reportSource;
  const source = sourceType === 'llm' || sourceType === 'llm_validated'
    ? 'AI explanation · checked against findings'
    : 'Template explanation';
  const subject = item.subject ?? {};
  const simulationNotice = typeof item.simulation_notice === 'string' ? item.simulation_notice.trim() : '';
  const subjectName = typeof subject.name === 'string' ? subject.name : '';
  const subjectVersion = typeof subject.version === 'string' ? subject.version : '';

  return `<article class="finding">
    <div class="finding-top"><span class="eyebrow">${esc(item.module)} / ${esc(item.id)}</span>
      <span class="pill sev-${esc(String(item.severity).toLowerCase())}">${esc(item.severity)}</span>
      ${isSimulation(item) ? '<span class="pill sim">SIMULATION</span>' : ''}
    </div>
    <h3>${esc(item.title)}</h3>
    <p class="facts">${esc(item.confidence)} confidence${subjectName ? ` · ${esc(subjectName)}` : ''}${subjectVersion ? ` ${esc(subjectVersion)}` : ''}</p>
    ${explanation.plain_explanation ? `<p>${esc(explanation.plain_explanation)}</p>` : ''}
    ${explanation.why_it_matters ? `<p class="why"><strong>Why it matters</strong> ${esc(explanation.why_it_matters)}</p>` : ''}
    ${actions ? `<div class="action"><strong>Suggested next step</strong><ul>${actions}</ul></div>` : ''}
    ${simulationNotice ? `<p class="simulation-notice"><strong>SIMULATION</strong> ${esc(simulationNotice)}</p>` : ''}
    ${explanation.limitations ? `<p class="limit">${esc(explanation.limitations)}</p>` : ''}
    <p class="source">${esc(source)}</p>
    <details><summary>Inspect evidence</summary><pre>${esc(JSON.stringify({ subject, evidence }, null, 2))}</pre></details>
  </article>`;
}

function render(report: Report, standalone: boolean): string {
  const nonce = crypto.randomBytes(16).toString('hex');
  const items = Array.isArray(report.items) ? report.items : [];
  const groups = new Map<string, ReportItem[]>();
  for (const item of items) groups.set(item.category, [...(groups.get(item.category) ?? []), item]);

  const categories = [
    ...ORDER.filter((category) => groups.has(category)),
    ...[...groups.keys()].filter((category) => !(category in META))
  ];
  const sections = categories.map((category) => {
    const meta = META[category as Category];
    const findings = groups.get(category) ?? [];
    return `<section class="category ${meta?.tone ?? 'slate'}">
      <div class="category-head"><span>${esc(meta?.label ?? category)}</span><span class="count">${findings.length}</span></div>
      ${findings.map((item) => card(item, report.explanation_source)).join('')}
    </section>`;
  }).join('');

  const moduleStatus = report.module_status && typeof report.module_status === 'object'
    ? Object.entries(report.module_status).map(([name, value]) =>
      `<div class="module"><span>${esc(name)}</span><b>${esc(typeof value === 'string' ? value : JSON.stringify(value))}</b></div>`
    ).join('')
    : '';
  const reportLimitations = report.limitations ?? report.global_limitations ?? [];
  const limitations = Array.isArray(reportLimitations)
    ? reportLimitations.map((limitation) => `<li>${esc(limitation)}</li>`).join('')
    : '';
  const issueCount = items.filter((item) => item.category !== 'NO_KNOWN_ISSUES').length;

  const theme = standalone
    ? `:root{color-scheme:dark;--vscode-foreground:#e2e8ed;--vscode-editor-background:#101d2c;--vscode-panel-border:#33485c;--vscode-button-background:#73d7c2;--vscode-button-foreground:#101d2c;--vscode-editorWidget-background:#13253a;--vscode-textCodeBlock-background:#0b1724;--vscode-button-border:#40576b}`
    : ':root{color-scheme:light dark}';
  const csp = standalone
    ? `default-src 'none'; style-src 'nonce-${nonce}';`
    : `default-src 'none'; style-src 'nonce-${nonce}'; script-src 'nonce-${nonce}';`;
  const exportButton = standalone ? '' : '<div class="actions"><button id="export">Export report</button></div>';
  const script = standalone ? '' : `<script nonce="${nonce}">
    const vscode = acquireVsCodeApi();
    document.getElementById('export').addEventListener('click', () => vscode.postMessage({type:'export'}));
  </script>`;
  const summary = issueCount
    ? `${issueCount} finding${issueCount === 1 ? '' : 's'} to review`
    : 'Checks complete';
  const simulationBanner = report.simulation_present
    ? '<aside class="simulation-banner"><strong>SIMULATION</strong> This report includes findings from a compiler wrapper made by the BuildGuard team for demonstration.</aside>'
    : '';

  return `<!doctype html>
<html><head><meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="${csp}">
<meta name="viewport" content="width=device-width, initial-scale=1">
<style nonce="${nonce}">
${theme}
*{box-sizing:border-box}body{margin:0;padding:28px 34px 48px;color:var(--vscode-foreground);font-family:var(--vscode-font-family,Arial,sans-serif);background:var(--vscode-editor-background);line-height:1.55;max-width:1120px}
.mast{display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid var(--vscode-panel-border);padding-bottom:20px}.brand{display:flex;gap:14px;align-items:center}.mark{width:40px;height:40px;border-radius:13px;background:linear-gradient(145deg,#5ed6c2,#54a6ff);color:#071820;display:grid;place-items:center;font-size:22px;font-weight:800}
.kicker,.eyebrow,.source,.facts{font-size:11px;letter-spacing:.08em;text-transform:uppercase;opacity:.68}.kicker{margin:0 0 2px}.mast h1{font-size:23px;letter-spacing:-.03em;margin:0}.actions button{border:1px solid var(--vscode-button-border,var(--vscode-panel-border));background:var(--vscode-button-background);color:var(--vscode-button-foreground);border-radius:8px;padding:8px 13px;cursor:pointer;font:inherit}
.hero{display:grid;grid-template-columns:1fr auto;gap:24px;align-items:center;padding:28px 0 20px}.hero h2{margin:0 0 5px;font-size:21px;letter-spacing:-.025em}.hero p{margin:0;opacity:.78;max-width:700px}.metric{border:1px solid var(--vscode-panel-border);border-radius:14px;padding:12px 18px;min-width:116px;text-align:center;background:var(--vscode-editorWidget-background)}.metric strong{display:block;font-size:28px;line-height:1.2}.metric span{font-size:10px;letter-spacing:.1em;text-transform:uppercase;opacity:.68}.meta{font-size:11px;opacity:.58;margin-top:9px}
.overview{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:9px;margin:14px 0 30px}.module{border:1px solid var(--vscode-panel-border);border-radius:10px;padding:10px 13px;display:flex;justify-content:space-between;gap:10px;font-size:12px}.module b{font-weight:600;opacity:.82}
.category{margin:26px 0 34px;padding-left:14px;border-left:2px solid #8492a6}.category.critical,.category.high{border-color:#e76c62}.category.violet{border-color:#bd8be9}.category.amber{border-color:#e2b35b}.category.green{border-color:#62ba92}.category-head{display:flex;align-items:center;gap:9px;font-size:13px;font-weight:700;margin:0 0 13px}.count{font-size:11px;opacity:.65;border:1px solid var(--vscode-panel-border);border-radius:20px;padding:0 7px}
.finding{border:1px solid var(--vscode-panel-border);border-radius:12px;padding:16px 18px;margin:10px 0;background:var(--vscode-editorWidget-background);box-shadow:0 5px 18px #0000000a}.finding-top{display:flex;align-items:center;gap:7px;flex-wrap:wrap}.eyebrow{margin-right:auto}.pill{border-radius:20px;padding:2px 9px;font-size:10px;font-weight:700;letter-spacing:.06em;background:#6b778522}.sev-critical,.sev-high{background:#ef776322;color:#f29189}.sev-medium{background:#e7ad3a22;color:#e7be70}.sev-low,.sev-info{background:#5ca5da22;color:#80bbe5}.sim{background:#71809633;color:#a9bad2}.finding h3{margin:7px 0 2px;font-size:16px}.facts,.source{font-size:10px;letter-spacing:.04em;margin:0 0 11px}.finding p{margin:9px 0}.why,.action{padding:10px 12px;border-radius:7px;background:var(--vscode-editor-background)}.action ul{margin:4px 0 0;padding-left:20px}.limit{font-size:12px;opacity:.72}.source{margin:12px 0 7px}details{border-top:1px solid var(--vscode-panel-border);padding-top:9px}summary{cursor:pointer;font-size:12px;opacity:.8}pre{overflow:auto;padding:12px;border-radius:8px;background:var(--vscode-textCodeBlock-background);font-size:11px;white-space:pre-wrap;overflow-wrap:anywhere}
.simulation-banner,.simulation-notice{border:1px solid #b78a48;border-radius:8px;padding:10px 13px;background:#b78a4818;color:var(--vscode-foreground)}
.empty{padding:22px;border:1px dashed var(--vscode-panel-border);border-radius:12px;opacity:.72}.limits{margin-top:34px;padding-top:20px;border-top:1px solid var(--vscode-panel-border)}.limits h2{font-size:15px}.limits li{font-size:12px;opacity:.8;margin:6px 0}@media(max-width:620px){body{padding:20px 16px}.hero{grid-template-columns:1fr}.metric{justify-self:start}.mast{align-items:flex-start;gap:12px}}
</style></head><body>
<header class="mast"><div class="brand"><div class="mark">B</div><div><p class="kicker">BuildGuard / Analysis</p><h1>Workspace report</h1></div></div>${exportButton}</header>
<main>${simulationBanner}<div class="hero"><div><h2>${summary}</h2><p>${esc(report.overall_summary)}</p><div class="meta">Scan ${esc(report.scan_id)} &nbsp;·&nbsp; ${esc(report.generated_at)}</div></div><div class="metric"><strong>${issueCount}</strong><span>Needs review</span></div></div>
<h2 class="kicker">Module status</h2><div class="overview">${moduleStatus || '<div class="module">No module status provided</div>'}</div>
${sections || '<div class="empty">No findings were returned. Review module status and limitations below to understand which checks ran.</div>'}
<div class="limits"><h2>Limits of this report</h2><ul>${limitations || '<li>Results cover only the checks that completed and the evidence they produced.</li>'}</ul></div></main>${script}</body></html>`;
}
