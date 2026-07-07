const { createSign } = require('crypto');
const https = require('https');
const querystring = require('querystring');

let cachedToken = null;
let tokenExpiry = null;

function generateJWT() {
  const serviceAccount = process.env.UNICO_SERVICE_ACCOUNT;
  const privateKeyPem = process.env.UNICO_PRIVATE_KEY;
  const authUrl = process.env.UNICO_AUTH_URL || 'https://identity.acesso.io';

  if (!serviceAccount || !privateKeyPem) throw new Error('Credenciais nao configuradas');

  const now = Math.floor(Date.now() / 1000);
  const b64url = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64')
    .replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');

  const signingInput = `${b64url({alg:'RS256',typ:'JWT'})}.${b64url({iss:serviceAccount,scope:'*',aud:authUrl,exp:now+3600,iat:now})}`;
  const pem = privateKeyPem.replace(/\\n/g, '\n');
  const sign = createSign('RSA-SHA256');
  sign.update(signingInput);
  const sig = sign.sign(pem, 'base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
  return `${signingInput}.${sig}`;
}

// Usa o módulo https nativo para evitar problema de redirect do fetch
function postForm(url, body) {
  return new Promise((resolve, reject) => {
    const data = querystring.stringify(body);
    const parsed = new URL(url);
    const opts = {
      hostname: parsed.hostname,
      path: parsed.pathname + parsed.search,
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(data),
      },
    };
    const req = https.request(opts, (res) => {
      // Segue um redirect manualmente se necessário
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        console.log('[auth] redirect para:', res.headers.location);
        return postForm(res.headers.location, body).then(resolve).catch(reject);
      }
      let raw = '';
      res.on('data', chunk => raw += chunk);
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

  const authUrl = process.env.UNICO_AUTH_URL || 'https://identity.acesso.io';
  console.log('[auth] autenticando em:', authUrl);

  const jwt = generateJWT();
  console.log('[auth] JWT gerado, tamanho:', jwt.length);

  const result = await postForm(authUrl, {
    grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
    assertion: jwt,
  });

  console.log('[auth] resposta status:', result.status);

  if (result.status !== 200) {
    throw new Error(`Auth falhou (${result.status}): ${result.body}`);
  }

  const data = JSON.parse(result.body);
  cachedToken = data.access_token;
  tokenExpiry = now + (data.expires_in || 3600);
  console.log('[auth] token OK');
  return cachedToken;
}

module.exports = { getAccessToken };
