const { createSign } = require('crypto');
const https = require('https');
const querystring = require('querystring');

let cachedToken = null;
let tokenExpiry = null;

const AUTH_URL = 'https://identity.acesso.io/auth/idp';

function generateJWT() {
  const serviceAccount = process.env.UNICO_SERVICE_ACCOUNT;
  const privateKeyPem = process.env.UNICO_PRIVATE_KEY;
  if (!serviceAccount || !privateKeyPem) throw new Error('Credenciais nao configuradas');
  const now = Math.floor(Date.now() / 1000);
  const b64url = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64')
    .replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
  const signingInput = `${b64url({alg:'RS256',typ:'JWT'})}.${b64url({iss:serviceAccount,scope:'*',aud:AUTH_URL,exp:now+3600,iat:now})}`;
  const pem = privateKeyPem.replace(/\\n/g, '\n');
  const sign = createSign('RSA-SHA256');
  sign.update(signingInput);
  return `${signingInput}.${sign.sign(pem,'base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'')}`;
}

function httpRequest(url, method, body, headers) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const data = body ? querystring.stringify(body) : null;
    const reqHeaders = { ...headers };
    if (data) reqHeaders['Content-Length'] = Buffer.byteLength(data);
    const req = https.request({
      hostname: parsed.hostname,
      path: parsed.pathname + parsed.search,
      method,
      headers: reqHeaders,
    }, (res) => {
      let raw = '';
      res.on('data', c => raw += c);
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: raw }));
    });
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

async function getAccessToken() {
  const now = Math.floor(Date.now() / 1000);
  if (cachedToken && tokenExpiry && now < tokenExpiry - 600) return cachedToken;
  console.log('[auth] autenticando em:', AUTH_URL);
  const jwt = generateJWT();
  const r1 = await httpRequest(AUTH_URL, 'POST', {
    grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
    assertion: jwt,
  }, { 'Content-Type': 'application/x-www-form-urlencoded' });
  console.log('[auth] r1 status:', r1.status, '| location:', r1.headers.location, '| body:', r1.body.slice(0,300));
  if (r1.status === 200) {
    const data = JSON.parse(r1.body);
    cachedToken = data.access_token;
    tokenExpiry = now + (data.expires_in || 3600);
    return cachedToken;
  }
  if (r1.status >= 300 && r1.status < 400 && r1.headers.location) {
    const loc = r1.headers.location;
    const next = loc.startsWith('http') ? loc : `https://identity.acesso.io${loc}`;
    console.log('[auth] seguindo para:', next);
    const r2 = await httpRequest(next, 'POST', {
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: jwt,
    }, { 'Content-Type': 'application/x-www-form-urlencoded' });
    console.log('[auth] r2 status:', r2.status, '| location:', r2.headers.location, '| body:', r2.body.slice(0,300));
    if (r2.status === 200) {
      const data = JSON.parse(r2.body);
      cachedToken = data.access_token;
      tokenExpiry = now + (data.expires_in || 3600);
      return cachedToken;
    }
    throw new Error(`Auth r2 falhou (${r2.status}): ${r2.body}`);
  }
  throw new Error(`Auth falhou (${r1.status}): ${r1.body}`);
}

module.exports = { getAccessToken };
