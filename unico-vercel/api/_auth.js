const { createSign } = require('crypto');
const https = require('https');
const querystring = require('querystring');

let cachedToken = null;
let tokenExpiry = null;

function makeJWT(sa, pk, aud) {
  const now = Math.floor(Date.now() / 1000);
  const b64url = (o) => Buffer.from(JSON.stringify(o)).toString('base64')
    .replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
  const si = `${b64url({alg:'RS256',typ:'JWT'})}.${b64url({iss:sa,scope:'*',aud,exp:now+3600,iat:now})}`;
  const pem = pk.replace(/\\n/g,'\n');
  const s = createSign('RSA-SHA256');
  s.update(si);
  return `${si}.${s.sign(pem,'base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'')}`;
}

function post(url, body) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const data = querystring.stringify(body);
    const req = https.request({
      hostname: parsed.hostname,
      path: parsed.pathname + parsed.search,
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(data),
        'Accept': 'application/json',
      },
    }, (res) => {
      let raw = '';
      res.on('data', c => raw += c);
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: raw }));
    });
    req.on('error', (e) => reject(e));
    req.write(data);
    req.end();
  });
}

async function getAccessToken() {
  const now = Math.floor(Date.now() / 1000);
  if (cachedToken && tokenExpiry && now < tokenExpiry - 600) return cachedToken;

  const sa = process.env.UNICO_SERVICE_ACCOUNT;
  const pk = process.env.UNICO_PRIVATE_KEY;
  const base = 'https://identity.acesso.io';

  const candidates = [
    `${base}/auth/realms/acesso-rh/protocol/openid-connect/token`,
    `${base}/auth/realms/unico/protocol/openid-connect/token`,
    `${base}/auth/realms/people/protocol/openid-connect/token`,
    `${base}/auth/realms/master/protocol/openid-connect/token`,
    `${base}/auth/realms/plataforma/protocol/openid-connect/token`,
    `${base}/realms/acesso-rh/protocol/openid-connect/token`,
    `${base}/realms/unico/protocol/openid-connect/token`,
    `${base}/realms/master/protocol/openid-connect/token`,
  ];

  for (const url of candidates) {
    try {
      const jwt = makeJWT(sa, pk, base);
      const r = await post(url, {
        grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        assertion: jwt,
      });
      console.log(`[auth] ${url} -> ${r.status} | ${r.body.slice(0,120)}`);
      if (r.status === 200) {
        const data = JSON.parse(r.body);
        cachedToken = data.access_token;
        tokenExpiry = now + (data.expires_in || 3600);
        console.log('[auth] sucesso:', url);
        return cachedToken;
      }
    } catch(e) {
      console.log(`[auth] ${url} -> ERROR: ${e.message}`);
    }
  }

  throw new Error('Nenhum endpoint Keycloak funcionou — veja logs acima');
}

module.exports = { getAccessToken };
