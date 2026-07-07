const axios = require('axios');
const forge = require('node-forge');

let cachedToken = null;
let tokenExpiry = null;

async function getAccessToken() {
  const now = Math.floor(Date.now() / 1000);
  if (cachedToken && tokenExpiry && now < tokenExpiry - 600) return cachedToken;

  const serviceAccount = process.env.UNICO_SERVICE_ACCOUNT;
  const privateKeyPem = process.env.UNICO_PRIVATE_KEY;
  const authUrl = process.env.UNICO_AUTH_URL || 'https://identity.acesso.io';

  if (!serviceAccount || !privateKeyPem) throw new Error('Credenciais nao configuradas');

  const header = { alg: 'RS256', typ: 'JWT' };
  const payload = {
    iss: serviceAccount,
    scope: '*',
    aud: authUrl,
    exp: now + 3600,
    iat: now,
  };

  const b64url = (obj) =>
    Buffer.from(JSON.stringify(obj))
      .toString('base64')
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

  const signingInput = `${b64url(header)}.${b64url(payload)}`;

  const pemNormalized = privateKeyPem.replace(/\\n/g, '\n');
  const privateKey = forge.pki.privateKeyFromPem(pemNormalized);
  const md = forge.md.sha256.create();
  md.update(signingInput, 'utf8');
  const signature = privateKey.sign(md);
  const sig = Buffer.from(signature, 'binary')
    .toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

  const jwt = `${signingInput}.${sig}`;

  const response = await axios.post(
    authUrl,
    new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: jwt,
    }),
    { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
  );

  cachedToken = response.data.access_token;
  tokenExpiry = now + (response.data.expires_in || 3600);
  return cachedToken;
}

module.exports = { getAccessToken };
