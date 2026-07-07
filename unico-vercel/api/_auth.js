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
  const signingInput = `${b64url({alg:'RS256',typ:'JWT'})}.${b64url({iss:process.env.UNICO_SERVICE_ACCOUNT,scope:'*',aud:AUTH_URL,exp:now+3600,iat:now})}`;
  const pem = privateKeyPem.replace(/\\n/g, '\n');
  const sign = createSign('RSA-SHA256');
  sign.update(signingInput);
  return `${signingInput}.${sign.sign(pem,'base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'')}`;
}

function postForm(url, body) {
  return new Promise((resolve, reject) => {
    const data = querystring.stringify(body);
    const parsed = new URL(url);
    const req = https.request({
      hostname: parsed.hostname,
      path: parsed.pathname + parsed.search,
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(data) },
    }, (res) => {
      let raw = '';
      res.on('data', c => raw += c);
      res.on('end', () => resolve({ status: res.statusCode, body: raw }));
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

async function getAccessToken() {
  const now = Math.floor(Date.now() / 1000);
  if (cachedToken && tokenExpiry && now < tokenExpiry - 600) return cachedToken;
  console.log('[auth] autenticando em:', AUTH_URL);
  const jwt = generateJWT();
  console.log('[auth] JWT tamanho:', jwt.length);
  const result = await postForm(AUTH_URL, {
    grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
    assertion: jwt,
  });
  console.log('[auth] status:', result.status, '| body:', result.body.slice(0, 300));
  if (result.status !== 200) throw new Error(`Auth falhou (${result.status}): ${result.body}`);
  const data = JSON.parse(result.body);
  cachedToken = data.access_token;
  tokenExpiry = now + (data.expires_in || 3600);
  return cachedToken;
}

module.exports = { getAccessToken };
