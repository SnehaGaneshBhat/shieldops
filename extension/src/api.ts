import type { Report, ScanRequest, ScanStatus } from './types';
export class ApiError extends Error { constructor(public status: number, message: string) { super(message); } }
const MAX_JSON_BYTES = 10 * 1024 * 1024;
export class BuildGuardClient {
  constructor(private cfg: () => { url: string; token: string }) {}
  private async readText(res: Response, limit: number, label: string): Promise<string> {
    const declaredLength = Number(res.headers.get('content-length'));
    if (Number.isFinite(declaredLength) && declaredLength > limit) throw new ApiError(res.status, `${label} exceeds the ${Math.floor(limit / (1024 * 1024))} MB size limit.`);
    const reader = res.body?.getReader();
    if (!reader) return '';
    const decoder = new TextDecoder(); let result = ''; let size = 0;
    try {
      for (;;) {
        const chunk = await reader.read();
        if (chunk.done) break;
        size += chunk.value.byteLength;
        if (size > limit) { await reader.cancel(); throw new ApiError(res.status, `${label} exceeds the ${Math.floor(limit / (1024 * 1024))} MB size limit.`); }
        result += decoder.decode(chunk.value, { stream: true });
      }
      return result + decoder.decode();
    } catch (e) {
      if (e instanceof ApiError) throw e;
      throw new ApiError(res.status, `${label} could not be read.`);
    }
  }
  private endpoint(path: string): URL {
    const { url } = this.cfg();
    let base: URL;
    try { base = new URL(url); }
    catch { throw new ApiError(-1, 'BuildGuard backend URL is invalid. Use a loopback URL such as http://127.0.0.1:8787.'); }
    const host = base.hostname.toLowerCase();
    const ipv4Parts = host.split('.');
    const loopbackV4 = ipv4Parts.length === 4 && ipv4Parts[0] === '127' && ipv4Parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255);
    const loopback = host === 'localhost' || host === '[::1]' || loopbackV4;
    if (!loopback || !['http:', 'https:'].includes(base.protocol) || base.username || base.password || (base.pathname !== '' && base.pathname !== '/') || base.search || base.hash) {
      throw new ApiError(-1, 'BuildGuard only sends its token to an HTTP(S) loopback URL. Use http://127.0.0.1:8787 or localhost.');
    }
    return new URL(path, base.origin);
  }
  private async req<T>(method: string, path: string, body?: unknown): Promise<T> {
    const { url, token } = this.cfg();
    let res: Response;
    let endpoint: URL;
    try { endpoint = this.endpoint(path); }
    catch (e) { if (e instanceof ApiError) throw e; throw new ApiError(-1, `Invalid BuildGuard URL ${url}: ${(e as Error).message}`); }
    try { res = await fetch(endpoint, { method, redirect: 'error', headers: { 'Accept': 'application/json', 'Content-Type': 'application/json', 'X-BuildGuard-Token': token }, body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(15000) }); }
    catch (e) { throw new ApiError(0, `Cannot reach BuildGuard at ${url}: ${(e as Error).message}`); }
    if (!res.ok) {
      let detail = '';
      try { detail = (await this.readText(res, 300, 'Error response')).slice(0, 300); } catch { /* retain the status if the body cannot be read */ }
      throw new ApiError(res.status, `${method} ${path} returned ${res.status}${detail ? `: ${detail}` : '.'}`);
    }
    const jsonText = await this.readText(res, MAX_JSON_BYTES, 'The backend response');
    try { return JSON.parse(jsonText) as T; }
    catch { throw new ApiError(res.status, `${method} ${path} returned invalid JSON.`); }
  }
  health() { return this.req<Record<string, unknown>>('GET', '/v1/health'); }
  async startScan(r: ScanRequest) {
    const result = await this.req<{ scan_id: string }>('POST', '/v1/scans', r);
    if (!result || typeof result.scan_id !== 'string' || result.scan_id.length === 0 || result.scan_id.length > 200) throw new ApiError(200, 'The backend response did not include a valid scan ID.');
    return result;
  }
  async getScan(id: string) {
    const status = await this.req<ScanStatus>('GET', `/v1/scans/${encodeURIComponent(id)}`);
    const states = ['queued', 'running', 'completed', 'completed_with_errors', 'failed', 'cancelled'];
    if (!status || status.scan_id !== id || typeof status.state !== 'string' || !states.includes(status.state) || !status.modules || typeof status.modules !== 'object' || Array.isArray(status.modules)) throw new ApiError(200, 'The backend returned an invalid scan status.');
    return status;
  }
  async getReport(id: string) {
    const report = await this.req<Report>('GET', `/v1/scans/${encodeURIComponent(id)}/report`);
    if (!report || report.scan_id !== id || typeof report.overall_summary !== 'string' || !Array.isArray(report.items) || report.items.some((item) => !item || typeof item.title !== 'string' || typeof item.category !== 'string')) throw new ApiError(200, 'The backend returned a report with an invalid shape.');
    return report;
  }
  cancel(id: string) { return this.req<unknown>('POST', `/v1/scans/${encodeURIComponent(id)}/cancel`, {}); }
}
