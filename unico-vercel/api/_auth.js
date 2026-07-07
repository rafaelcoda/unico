const { createSign } = require('crypto');
let cachedToken = null, tokenExpiry = null;
function generateJWT() {
  const serviceAccount = process.env.UNICO_SERVICE_ACCOUNT;
  const privateKeyPem = process.env.UNICO_PRIVATE_KEY;
  const authUrl = process.env.UNICO_AUTH_URL || 'https://identity.acesso.io';
  if (!serviceAccount || !privateKeyPem) throw new Error('Credenciais nao configuradas');
  const now = Math.floor(Date.now() / 1000);
  const b64url = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
  const signingInput = `${b64url({alg:'RS256',typ:'JWT'})}.${b64url({iss:serviceAccount,scope:'*',aud:authUrl,exp:now+3600,iat:now})}`;
  const sign = createSign('RSA-SHA256');
  sign.update(signingInput);
  return `${signingInput}.${sign.sign(privateKeyPem.replace(/\\n/g,'\n'),'base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'')}`;
}
async function getAccessToken() {
  const now = Math.floor(Date.now() / 1000);
  if (cachedToken && tokenExpiry && now < tokenExpiry - 600) return cachedToken;
  const jwt = generateJWT();
  const authUrl = process.env.UNICO_AUTH_URL || 'https://identity.acesso.io';
  const resp = await fetch(authUrl, { method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body: new URLSearchParams({grant_type:'urn:ietf:params:oauth:grant-type:jwt-bearer',assertion:jwt}) });
  if (!resp.ok) throw new Error(`Auth falhou (${resp.status}): ${await resp.text()}`);
  const data = await resp.json();
  cachedToken = data.access_token;
  tokenExpiry = now + (data.expires_in || 3600);
  return cachedToken;
}
module.exports = { getAccessToken };
