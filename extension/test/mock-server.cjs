'use strict';
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { randomUUID } = require('node:crypto');
const report = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', 'report.sample.json'), 'utf8'));
const scans = new Map();
const token = process.env.BUILDGUARD_TOKEN || 'buildguard-local-mock-token';
const server = http.createServer((req, res) => {
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  if (req.headers['x-buildguard-token'] !== token) { res.writeHead(401); return res.end(JSON.stringify({detail:'invalid token'})); }
  if (req.method === 'GET' && req.url === '/v1/health') { res.writeHead(200); return res.end(JSON.stringify({status:'ok',mock:true})); }
  if (req.method === 'POST' && req.url === '/v1/scans') {
    let body=''; let size=0; let tooLarge=false;
    req.on('data', chunk => { if (tooLarge) return; size += chunk.length; if (size > 1024 * 1024) { tooLarge=true; res.writeHead(413); res.end(JSON.stringify({detail:'request too large'})); req.resume(); return; } body += chunk; }); req.on('end', () => {
      if (tooLarge) return;
      let reqBody; try { reqBody=JSON.parse(body); } catch { res.writeHead(400); return res.end(JSON.stringify({detail:'invalid JSON'})); }
      const id=`mock-${randomUUID()}`; scans.set(id,{created:Date.now(),body:reqBody,step:-1});
      while (scans.size > 50) scans.delete(scans.keys().next().value);
      res.writeHead(202); res.end(JSON.stringify({scan_id:id}));
    }); return;
  }
  const htmlMatch = req.method === 'GET' && req.url.match(/^\/v1\/scans\/([^/]+)\/report\.html$/);
  if (htmlMatch) {
    const id = decodeURIComponent(htmlMatch[1]); if (!scans.has(id)) { res.writeHead(404); return res.end(JSON.stringify({detail:'scan not found'})); }
    res.writeHead(200, {'Content-Type':'text/html; charset=utf-8'});
    return res.end('<!doctype html><meta charset="utf-8"><title>BuildGuard mock</title><h1>BuildGuard mock report</h1><p>Seven-category layout fixture. No real scan was run.</p>');
  }
  const match = req.url.match(/^\/v1\/scans\/([^/]+)(?:\/(report|cancel))?$/);
  if (match) {
    const id=decodeURIComponent(match[1]); if(!scans.has(id)){res.writeHead(404);return res.end(JSON.stringify({detail:'scan not found'}));}
    if (req.method === 'GET' && match[2] === 'report') { res.writeHead(200); return res.end(JSON.stringify({...report,scan_id:id})); }
    if (req.method === 'POST' && match[2] === 'cancel') { res.writeHead(200); return res.end(JSON.stringify({state:'cancelled'})); }
    if (req.method !== 'GET' || match[2]) { res.writeHead(405); return res.end(JSON.stringify({detail:'method not allowed'})); }
    const scan = scans.get(id); scan.step = Math.min(scan.step + 1, 4);
    const states = [
      {state:'queued',modules:{dependency:'queued',build:'queued',compiler:'queued'}},
      {state:'running',modules:{dependency:'running',build:'queued',compiler:'queued'}},
      {state:'running',modules:{dependency:'completed',build:'running',compiler:'queued'}},
      {state:'running',modules:{dependency:'completed',build:'completed',compiler:'running'}},
      {state:'completed',modules:{dependency:'completed',build:'completed',compiler:'completed'}}
    ];
    const current = states[scan.step];
    res.writeHead(200);return res.end(JSON.stringify({scan_id:id,...current,errors:[],started_at:new Date(scan.created).toISOString()}));
  }
  res.writeHead(404); res.end(JSON.stringify({detail:'not found'}));
});
const port=Number(process.env.BUILDGUARD_MOCK_PORT||8788);
server.listen(port,'127.0.0.1',()=>console.log(`BuildGuard mock listening at http://127.0.0.1:${port}`));
for(const signal of ['SIGINT','SIGTERM']) process.on(signal,()=>server.close(()=>process.exit(0)));
