'use strict';

const axios = require('axios');
const https = require('https');

// ─────────────────────────────────────────────
// Agente HTTPS com keepAlive para reuso de conexões
// Nota: keepAlive tem benefício limitado em serverless (instâncias efêmeras),
// mas não tem custo e ajuda em invocações "warm".
// ─────────────────────────────────────────────
const keepAliveAgent = new https.Agent({ keepAlive: true, rejectUnauthorized: true });

// ─────────────────────────────────────────────
// Configuração — lazy
// ─────────────────────────────────────────────
let _config = null;

function loadConfig() {
  if (_config) return _config;

  const clientId     = process.env.BB_CLIENT_ID;
  const clientSecret = process.env.BB_CLIENT_SECRET;
  const appKey       = process.env.BB_APP_KEY;
  const baseUrl      = process.env.BB_BASE_URL;
  const tokenUrl     = process.env.BB_TOKEN_URL;

  const missing = [];
  if (!clientId)     missing.push('BB_CLIENT_ID');
  if (!clientSecret) missing.push('BB_CLIENT_SECRET');
  if (!appKey)       missing.push('BB_APP_KEY');
  if (!baseUrl)      missing.push('BB_BASE_URL');
  if (!tokenUrl)     missing.push('BB_TOKEN_URL');

  if (missing.length > 0) {
    throw new Error(
      `Variáveis de ambiente do Banco do Brasil ausentes: ${missing.join(', ')}.`
    );
  }

  _config = { clientId, clientSecret, appKey, baseUrl, tokenUrl };
  return _config;
}

// ─────────────────────────────────────────────
// Cache de token
// ─────────────────────────────────────────────
let tokenCache   = null;
let tokenPromise = null;

const TOKEN_REFRESH_MARGIN_MS = 2 * 60 * 1000;

function isCacheValid() {
  return (
    tokenCache?.token &&
    tokenCache?.expiresAt &&
    Date.now() < tokenCache.expiresAt - TOKEN_REFRESH_MARGIN_MS
  );
}

async function fetchNewToken() {
  const { clientId, clientSecret, tokenUrl } = loadConfig();

  const body = new URLSearchParams({
    grant_type:    'client_credentials',
    client_id:     clientId,
    client_secret: clientSecret,
    scope:         'extrato-info',
  });

  const response = await axios.post(tokenUrl, body.toString(), {
    httpsAgent: keepAliveAgent,
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    // Token é blocking para toda chamada subsequente — timeout curto para não
    // estourar o budget total (token 10s + API 20s = 30s < limite Vercel).
    timeout: 10_000,
  });

  const { access_token, expires_in } = response.data;

  if (!access_token) {
    throw new Error('Token não retornado pelo Banco do Brasil.');
  }

  tokenCache = {
    token:     access_token,
    expiresAt: Date.now() + (expires_in ?? 3600) * 1000,
  };

  return tokenCache.token;
}

async function getAccessToken() {
  if (isCacheValid()) return tokenCache.token;

  if (!tokenPromise) {
    tokenPromise = fetchNewToken().finally(() => { tokenPromise = null; });
  }

  return tokenPromise;
}

// ─────────────────────────────────────────────
// Consulta de Extrato — Conta Corrente
//
// Endpoint:
//   GET /conta-corrente/agencia/{agencia}/conta/{conta}
//
// Query params:
//   numeroPaginaSolicitacao             — padrão 1   (mín 1)
//   quantidadeRegistroPaginaSolicitacao — padrão 200 (mín 50, máx 200)
//   dataInicioSolicitacao / dataFimSolicitacao — integer DDMMAAAA
//     ex: 1052025 para 01/05/2025, 1012025 para 01/01/2025
//     A string DDMMAAAA é convertida para integer removendo o zero leading
//     (parseInt("01052025", 10) → 1052025), que é exatamente o que a spec BB
//     define como tipo "integer" para esse campo.
//
// gw-dev-app-key enviada como HEADER (não query param) para evitar
// vazamento em logs de CDN, proxies e histórico de redirects.
// ─────────────────────────────────────────────
async function consultarExtratoBB({
  agencia,
  conta,
  dataInicio,
  dataFim,
  numeroPagina  = 1,
  tamanhoPagina = 200,
}) {
  const { appKey, baseUrl } = loadConfig();
  const token = await getAccessToken();

  const params = {
    numeroPaginaSolicitacao:             numeroPagina,
    quantidadeRegistroPaginaSolicitacao: tamanhoPagina,
  };

  if (dataInicio) params.dataInicioSolicitacao = parseInt(dataInicio, 10);
  if (dataFim)    params.dataFimSolicitacao    = parseInt(dataFim, 10);

  const path = `/conta-corrente/agencia/${encodeURIComponent(agencia)}/conta/${encodeURIComponent(conta)}`;

  const response = await axios.get(`${baseUrl}${path}`, {
    httpsAgent: keepAliveAgent,
    params,
    headers: {
      Authorization:    `Bearer ${token}`,
      Accept:           'application/json',
      // Issue #1 fix: app-key como header em vez de query param,
      // evitando vazamento em logs de CDN/proxy/redirects.
      'gw-dev-app-key': appKey,
    },
    timeout: 20_000,
  });

  return response.data;
}

module.exports = { consultarExtratoBB };
