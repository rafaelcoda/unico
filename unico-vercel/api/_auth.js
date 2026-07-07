const { createSign } = require('crypto');
const https = require('https');
const querystring = require('querystring');

let cachedToken = null;
let tokenExpiry = null;

const AUTH_URL = 'https://auth.acesso.io';

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

  // Testa as duas combinações mais prováveis
  const combos = [
    { url: AUTH_URL, aud: AUTH_URL },
    { url: AUTH_URL, aud: 'https://identity.acesso.io' },
  ];

  for (const { url, aud } of combos) {
    const jwt = makeJWT(sa, pk, aud);
    const r = await post(url, {
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: jwt,
    });
    console.log(`[auth] url=${url} aud=${aud} status=${r.status} loc=${r.headers.location||'-'} body=${r.body.slice(0,200)}`);
    if (r.status === 200) {
      const data = JSON.parse(r.body);
      cachedToken = data.access_token;
      tokenExpiry = now + (data.expires_in || 3600);
      return cachedToken;
    }
  }

  throw new Error('auth.acesso.io falhou — veja logs');
}

module.exports = { getAccessToken };
