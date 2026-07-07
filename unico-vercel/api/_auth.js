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
  const signingInput = `${b64url({alg:'RS256',typ:'JWT'})}.${b64url({
    iss: serviceAccount, scope: '*', aud: AUTH_URL, exp: now+3600, iat: now,
  })}`;
  const pem = privateKeyPem.replace(/\\n/g, '\n');
  const sign = createSign('RSA-SHA256');
  sign.update(signingInput);
  return `${signingInput}.${sign.sign(pem,'base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'')}`;
}

function httpRequest(url, method, body, extraHeaders = {}) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const data = body ? querystring.stringify(body) : '';
    const req = https.request({
      hostname: parsed.hostname,
      path: parsed.pathname + parsed.search,
      method,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(data),
        ...extraHeaders,
      },
    }, (res) => {
      let raw = '';
      res.on('data', c => raw += c);
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: raw }));
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

function extractCookies(headers) {
  const setCookie = headers['set-cookie'];
  if (!setCookie) return '';
  return setCookie.map(c => c.split(';')[0]).join('; ');
}

async function getAccessToken() {
  const now = Math.floor(Date.now() / 1000);
  if (cachedToken && tokenExpiry && now < tokenExpiry - 600) return cachedToken;

  console.log('[auth] iniciando em:', AUTH_URL);
  const jwt = generateJWT();
  const body = { grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion: jwt };

  const r0 = await httpRequest(AUTH_URL, 'GET', null, {});
  const cookies = extractCookies(r0.headers);
  console.log('[auth] GET status:', r0.status, '| cookies:', cookies.slice(0,100), '| location:', r0.headers.location);

  const r1 = await httpRequest(AUTH_URL, 'POST', body, cookies ? { Cookie: cookies } : {});
  console.log('[auth] POST status:', r1.status, '| location:', r1.headers.location, '| body:', r1.body.slice(0,300));

  if (r1.status === 200) {
    const data = JSON.parse(r1.body);
    cachedToken = data.access_token;
    tokenExpiry = now + (data.expires_in || 3600);
    return cachedToken;
  }

  if (r1.status >= 300 && r1.status < 400 && r1.headers.location) {
    const cookies2 = extractCookies(r1.headers) || cookies;
    const loc = r1.headers.location;
    const next = loc.startsWith('http') ? loc : `https://identity.acesso.io${loc}`;
    console.log('[auth] redirect para:', next);
    const r2 = await httpRequest(next, 'POST', body, cookies2 ? { Cookie: cookies2 } : {});
    console.log('[auth] r2 status:', r2.status, '| body:', r2.body.slice(0,300));
    if (r2.status === 200) {
      const data = JSON.parse(r2.body);
      cachedToken = data.access_token;
      tokenExpiry = now + (data.expires_in || 3600);
      return cachedToken;
    }
    throw new Error(`Auth r2 (${r2.status}): ${r2.body.slice(0,200)}`);
  }

  throw new Error(`Auth (${r1.status}): ${r1.body.slice(0,200)}`);
}

module.exports = { getAccessToken };
