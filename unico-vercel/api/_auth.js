const { createSign } = require('crypto');
const https = require('https');
const querystring = require('querystring');

let cachedToken = null;
let tokenExpiry = null;

function makeJWT(serviceAccount, privateKeyPem, aud) {
  const now = Math.floor(Date.now() / 1000);
  const b64url = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64')
    .replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
  const si = `${b64url({alg:'RS256',typ:'JWT'})}.${b64url({iss:serviceAccount,scope:'*',aud,exp:now+3600,iat:now})}`;
  const pem = privateKeyPem.replace(/\\n/g,'\n');
  const sign = createSign('RSA-SHA256');
  sign.update(si);
  return `${si}.${sign.sign(pem,'base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'')}`;
}

function post(url, body) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const data = querystring.stringify(body);
    const req = https.request({
      hostname: parsed.hostname, path: parsed.pathname + parsed.search, method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(data) },
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

async function getAccessToken() {
  const now = Math.floor(Date.now() / 1000);
  if (cachedToken && tokenExpiry && now < tokenExpiry - 600) return cachedToken;

  const sa = process.env.UNICO_SERVICE_ACCOUNT;
  const pk = process.env.UNICO_PRIVATE_KEY;

  const combos = [
    { url: 'https://identity.acesso.io/auth/idp',                                                    aud: 'https://identity.acesso.io' },
    { url: 'https://identity.acesso.io/auth/idp',                                                    aud: 'https://identity.acesso.io/auth/idp' },
    { url: 'https://identity.acesso.io/auth/realms/plataforma-acesso/protocol/openid-connect/token', aud: 'https://identity.acesso.io' },
    { url: 'https://identity.acesso.io/auth/realms/acesso/protocol/openid-connect/token',            aud: 'https://identity.acesso.io' },
    { url: 'https://identity.acesso.io/oauth/token',                                                 aud: 'https://identity.acesso.io' },
  ];

  for (const { url, aud } of combos) {
    try {
      const jwt = makeJWT(sa, pk, aud);
      const r = await post(url, { grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion: jwt });
      console.log(`[auth] ${url} | aud=${aud} | status=${r.status} | loc=${r.headers.location} | body=${r.body.slice(0,150)}`);
      if (r.status === 200) {
        const data = JSON.parse(r.body);
        cachedToken = data.access_token;
        tokenExpiry = now + (data.expires_in || 3600);
        return cachedToken;
      }
    } catch(e) { console.log('[auth] erro:', e.message); }
  }

  throw new Error('Nenhuma combinacao funcionou — veja logs');
}

module.exports = { getAccessToken };
