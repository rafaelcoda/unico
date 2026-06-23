# Unico People Panel — Vercel

## Deploy em 3 passos

### 1. Variáveis de ambiente no Vercel

No painel do Vercel → Settings → Environment Variables, adicione:

| Variável | Valor |
|----------|-------|
| `UNICO_SERVICE_ACCOUNT` | O `iss` da sua conta de serviço |
| `UNICO_PRIVATE_KEY` | Conteúdo do `.key.pem` (cole tudo, incluindo `-----BEGIN...`) |
| `UNICO_API_URL` | `https://api.acessorh.com.br` |
| `UNICO_AUTH_URL` | `https://identity.acesso.io` |

> **UNICO_PRIVATE_KEY:** Cole o conteúdo completo do arquivo `.pem`.
> O Vercel preserva as quebras de linha automaticamente.

### 2. Deploy via CLI

```bash
npm i -g vercel
vercel --prod
```

### 3. Deploy via GitHub

1. Suba o projeto para um repositório GitHub
2. No Vercel: "Add New Project" → importe o repositório
3. Configure as variáveis de ambiente
4. Clique em Deploy

## Estrutura do projeto

```
unico-vercel/
├── api/
│   ├── _auth.js          # Geração JWT + cache de token
│   └── proxy/
│       └── [...path].js  # Handler único para todas as rotas
├── public/
│   └── index.html        # Frontend do painel
├── package.json
├── vercel.json
└── README.md
```

## Rotas disponíveis

Todas as chamadas do frontend vão para `/api/proxy/*` e são roteadas para a API Unico automaticamente.

Exemplos:
- `GET /api/proxy/organization`
- `GET /api/proxy/positions?acc=UID&status=400`
- `POST /api/proxy/positions`
- `GET /api/proxy/roles/ACC_UID`
- `GET /api/proxy/ibge?uf=SP&city=Campinas`
