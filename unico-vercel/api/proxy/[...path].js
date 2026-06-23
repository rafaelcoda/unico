const axios = require('axios');
const { getAccessToken } = require('./_auth');

const API = process.env.UNICO_API_URL || 'https://api.acessorh.com.br';

function client(token) {
  return axios.create({
    baseURL: API,
    headers: { Authorization: `Bearer ${token}` },
  });
}

// Mapeia GET /api/proxy?_path=/positions&acc=xxx  →  GET /v1/positions?acc=xxx
// Mapeia POST /api/proxy com body { _path, ...rest } → POST /v1/...
const ROUTES = {
  // Organização
  'GET /organization':              (q) => ({ method: 'get', url: '/v1/accounts' }),
  'GET /organization/:id/units':    (q, p) => ({ method: 'get', url: `/v1/accounts/${p.id}` }),
  // Posições
  'GET /positions':                 (q) => ({ method: 'get', url: '/v1/positions', params: q }),
  'GET /positions/:id':             (q, p) => ({ method: 'get', url: `/v1/positions/${p.id}`, params: q }),
  'POST /positions':                (q, p, b) => ({ method: 'post', url: `/v1/account/${b.unit}/json/position`, data: b }),
  'PUT /positions/status/:id':      (q, p, b) => ({ method: 'put', url: `/v1/positions/status/${p.id}`, data: b }),
  'DELETE /positions':              (q) => ({ method: 'delete', url: '/v1/positions', params: q }),
  'PATCH /positions/:id/benefits':  (q, p, b) => ({ method: 'patch', url: `/v1/positions/${p.id}/benefits`, data: b }),
  'GET /positions/:id/invite':      (q, p) => ({ method: 'get', url: `/v1/admissions/invite/${p.id}` }),
  'PUT /admissions/batch-update':   (q, p, b) => ({ method: 'put', url: `/v1/account/${b.acc}/admissions/batch-update`, data: b }),
  // Documentos
  'GET /available-documents':       () => ({ method: 'post', url: '/v1/config/available-documents', data: {} }),
  // Cargos
  'GET /roles/:acc':                (q, p) => ({ method: 'get', url: `/v1/role/${p.acc}`, params: q }),
  'POST /roles/:acc':               (q, p, b) => ({ method: 'post', url: `/v1/role/json/${p.acc}`, data: b }),
  'DELETE /roles':                  (q) => ({ method: 'delete', url: '/v1/role', params: q }),
  // Departamentos
  'GET /departments/:acc':          (q, p) => ({ method: 'get', url: `/v1/department/${p.acc}`, params: q }),
  'POST /departments/:acc':         (q, p, b) => ({ method: 'post', url: `/v1/department/json/${p.acc}`, data: b }),
  'DELETE /departments':            (q) => ({ method: 'delete', url: '/v1/department', params: q }),
  // Benefícios
  'GET /benefits':                  (q) => ({ method: 'get', url: '/v1/benefit/groups', params: q }),
  // Anexos
  'GET /attachments/:acc':          (q, p) => ({ method: 'get', url: `/v1/attachments/${p.acc}`, params: q }),
  // Webhooks
  'POST /webhooks':                 (q, p, b) => ({ method: 'post', url: '/v1/integrations/webhook', data: b }),
  'DELETE /webhooks':               (q) => ({ method: 'delete', url: '/v1/integrations/webhook', params: q }),
  // Modelos
  'GET /models':                    (q) => ({ method: 'get', url: '/v1/models', params: q }),
  // IBGE
  'GET /ibge':                      (q) => ({ method: 'get', url: '/v1/ibge/code', params: q }),
  // Export V2
  'POST /v2/positions/export':      (q, p, b) => ({ method: 'post', url: '/v2/positions/export', data: b }),
};

function matchRoute(method, path) {
  for (const [key, fn] of Object.entries(ROUTES)) {
    const [rMethod, rPath] = key.split(' ');
    if (rMethod !== method) continue;
    const rParts = rPath.split('/');
    const pParts = path.split('/');
    if (rParts.length !== pParts.length) continue;
    const params = {};
    let match = true;
    for (let i = 0; i < rParts.length; i++) {
      if (rParts[i].startsWith(':')) {
        params[rParts[i].slice(1)] = pParts[i];
      } else if (rParts[i] !== pParts[i]) {
        match = false; break;
      }
    }
    if (match) return { fn, params };
  }
  return null;
}

module.exports = async (req, res) => {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();

  // Extrai o path lógico: /api/[...path] → /positions, /roles/xxx, etc.
  const urlPath = req.url.split('?')[0].replace(/^\/api\/proxy/, '') || '/';
  const query = Object.fromEntries(new URL(req.url, 'http://x').searchParams);
  const body = req.body || {};
  const method = req.method.toUpperCase();

  const matched = matchRoute(method, urlPath);
  if (!matched) {
    return res.status(404).json({ error: `Rota não encontrada: ${method} ${urlPath}` });
  }

  try {
    const token = await getAccessToken();
    const config = matched.fn(query, matched.params, body);
    const { data } = await client(token).request(config);
    return res.status(200).json(data);
  } catch (err) {
    const status = err.response?.status || 500;
    const detail = err.response?.data || err.message;
    return res.status(status).json({ error: 'Erro na API Unico', detail });
  }
};
