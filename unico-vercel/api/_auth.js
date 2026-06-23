const axios = require('axios');
const forge = require('node-forge');

// Cache em memória (dura enquanto a função estiver "quente")
let cachedToken = null;
let tokenExpiry = null;

function generateJWT() {
  const serviceAccount = process.env.UNICO_SERVICE_ACCOUNT;
  const privateKeyPem = process.env.UNICO_PRIVATE_KEY; // chave inline no env
  const authUrl = process.env.UNICO_AUTH_URL || 'https://identity.acesso.io';

  if (!serviceAccount || !privateKeyPem) {
    throw new Error('Variáveis UNICO_SERVICE_ACCOUNT e UNICO_PRIVATE_KEY não configuradas');
  }

  const now = Math.floor(Date.now() / 1000);
  const payload = { iss: serviceAccount, scope: '*', aud: authUrl, exp: now + 3600, iat: now };
  const header = { alg: 'RS256', typ: 'JWT' };

  const b64url = (obj) =>
    Buffer.from(JSON.stringify(obj)).toString('base64')
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

  const signingInput = `${b64url(header)}.${b64url(payload)}`;

  // Suporta chave com \n literal (como fica em variável de ambiente)
  const pemNormalized = privateKeyPem.replace(/\\n/g, '\n');
  const privateKey = forge.pki.privateKeyFromPem(pemNormalized);
  const md = forge.md.sha256.create();
  md.update(signingInput, 'utf8');
  const sig = Buffer.from(privateKey.sign(md), 'binary')
    .toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

  return `${signingInput}.${sig}`;
}

async function getAccessToken() {
  const now = Math.floor(Date.now() / 1000);
  if (cachedToken && tokenExpiry && now < tokenExpiry - 600) return cachedToken;

  const jwt = generateJWT();
  const authUrl = process.env.UNICO_AUTH_URL || 'https://identity.acesso.io';

  const { data } = await axios.post(
    authUrl,
    new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: jwt,
    }),
    { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
  );

  cachedToken = data.access_token;
  tokenExpiry = now + (data.expires_in || 3600);
  return cachedToken;
}

module.exports = { getAccessToken };
