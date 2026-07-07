const { createSign } = require('crypto');

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

async function getAccessToken() {
  const now = Math.floor(Date.now() / 1000);
  if (cachedToken && tokenExpiry && now < tokenExpiry - 600) return cachedToken;

  const authUrl = process.env.UNICO_AUTH_URL || 'https://identity.acesso.io';
  console.log('[auth] gerando JWT para:', authUrl);

  let jwt;
  try {
    jwt = generateJWT();
    console.log('[auth] JWT gerado OK, tamanho:', jwt.length);
  } catch (e) {
    console.error('[auth] Erro ao gerar JWT:', e.message);
    throw e;
  }

  let resp;
  try {
    resp = await fetch(authUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        assertion: jwt,
      }),
    });
  } catch (e) {
    console.error('[auth] fetch error:', e.message, 'cause:', e.cause?.message, 'code:', e.cause?.code);
    throw new Error(`fetch falhou para ${authUrl}: ${e.message} | cause: ${e.cause?.message} | code: ${e.cause?.code}`);
  }

  if (!resp.ok) {
    const text = await resp.text();
    console.error('[auth] resposta erro:', resp.status, text);
    throw new Error(`Auth falhou (${resp.status}): ${text}`);
  }

  const data = await resp.json();
  cachedToken = data.access_token;
  tokenExpiry = now + (data.expires_in || 3600);
  console.log('[auth] token obtido OK');
  return cachedToken;
}

module.exports = { getAccessToken };
