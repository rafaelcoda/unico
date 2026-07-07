const { getAccessToken } = require('../_auth');

const API = process.env.UNICO_API_URL || 'https://api.acessorh.com.br';

async function apiCall(token, method, url) {
  return fetch(`${API}${url}`, {
    method,
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
  });
}

async function apiCallWithBody(token, method, url, body) {
  return fetch(`${API}${url}`, {
    method,
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

const ROUTES = {
  'GET /organization':              (q)       => ({ url: '/v1/accounts' }),
  'GET /organization/:id/units':    (q, p)    => ({ url: `/v1/accounts/${p.id}` }),
  'GET /v2/organization':           ()        => ({ url: '/v2/organization' }),
  'GET /positions':                 (q)       => ({ url: '/v1/positions', params: q }),
  'GET /positions/:id':             (q, p)    => ({ url: `/v1/positions/${p.id}`, params: q }),
  'POST /positions':                (q, p, b) => ({ url: `/v1/account/${b.unit}/json/position`, body: b }),
  'PUT /positions/status/:id':      (q, p, b) => ({ url: `/v1/positions/status/${p.id}`, body: b }),
  'DELETE /positions':              (q)       => ({ url: '/v1/positions', params: q }),
  'PATCH /positions/:id/benefits':  (q, p, b) => ({ url: `/v1/positions/${p.id}/benefits`, body: b }),
  'GET /positions/:id/invite':      (q, p)    => ({ url: `/v1/admissions/invite/${p.id}` }),
  'PUT /admissions/batch-update':   (q, p, b) => ({ url: `/v1/account/${b.acc}/admissions/batch-update`, body: b }),
  'GET /available-documents':       ()        => ({ url: '/v1/config/available-documents', forceMethod: 'POST' }),
  'GET /roles/:acc':                (q, p)    => ({ url: `/v1/role/${p.acc}`, params: q }),
  'POST /roles/:acc':               (q, p, b) => ({ url: `/v1/role/json/${p.acc}`, body: b }),
  'DELETE /roles':                  (q)       => ({ url: '/v1/role', params: q }),
  'GET /departments/:acc':          (q, p)    => ({ url: `/v1/department/${p.acc}`, params: q }),
  'POST /departments/:acc':         (q, p, b) => ({ url: `/v1/department/json/${p.acc}`, body: b }),
  'DELETE /departments':            (q)       => ({ url: '/v1/department', params: q }),
  'GET /benefits':                  (q)       => ({ url: '/v1/benefit/groups', params: q }),
  'GET /attachments/:acc':          (q, p)    => ({ url: `/v1/attachments/${p.acc}`, params: q }),
  'POST /webhooks':                 (q, p, b) => ({ url: '/v1/integrations/webhook', body: b }),
  'DELETE /webhooks':               (q)       => ({ url: '/v1/integrations/webhook', params: q }),
  'GET /models':                    (q)       => ({ url: '/v1/models', params: q }),
  'GET /ibge':                      (q)       => ({ url: '/v1/ibge/code', params: q }),
  'POST /v2/positions/export':      (q, p, b) => ({ url: '/v2/positions/export', body: b }),
};

function matchRoute(method, path) {
  for (const [key, fn] of Object.entries(ROUTES)) {
    const [rMethod, rPath] = key.split(' ');
    if (rMethod !== method) continue;
    const rParts = rPath.split('/').filter(Boolean);
    const pParts = path.split('/').filter(Boolean);
    if (rParts.length !== pParts.length) continue;
    const params = {};
    let ok = true;
    for (let i = 0; i < rParts.length; i++) {
      if (rParts[i].startsWith(':')) params[rParts[i].slice(1)] = pParts[i];
      else if (rParts[i] !== pParts[i]) { ok = false; break; }
    }
    if (ok) return { fn, params };
  }
  return null;
}

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();

  try {
    const full = req.url || '';
    const withoutPrefix = full.replace(/^\/api\/proxy/, '');
    const [pathPart, queryPart] = withoutPrefix.split('?');
    const logicalPath = pathPart || '/';

    const query = {};
    if (queryPart) {
      queryPart.split('&').forEach(part => {
        const [k, v] = part.split('=');
        if (k) query[decodeURIComponent(k)] = decodeURIComponent(v || '');
      });
    }

    const method = req.method.toUpperCase();
    const matched = matchRoute(method, logicalPath);

    if (!matched) {
      return res.status(404).json({ error: `Rota não encontrada: ${method} ${logicalPath}` });
    }

    const token = await getAccessToken();
    const config = matched.fn(query, matched.params, req.body || {});

    // Monta URL com query params
    let apiUrl = config.url;
    if (config.params) {
      const qs = Object.entries(config.params)
        .filter(([, v]) => v !== undefined && v !== '')
        .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
        .join('&');
      if (qs) apiUrl += `?${qs}`;
    }

    const finalMethod = config.forceMethod || method;
    const apiResp = config.body
      ? await apiCallWithBody(token, finalMethod, apiUrl, config.body)
      : await apiCall(token, finalMethod, apiUrl);

    const text = await apiResp.text();
    let data;
    try { data = JSON.parse(text); } catch { data = { raw: text }; }

    return res.status(apiResp.status).json(data);

  } catch (err) {
    console.error('[proxy error]', err.message);
    return res.status(500).json({ error: err.message });
  }
};
