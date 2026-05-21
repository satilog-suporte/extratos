'use strict';

const axios = require('axios');
const https = require('https');

// ─────────────────────────────────────────────
// Constantes
// ─────────────────────────────────────────────
const BASE_URL = 'https://openapi.bradesco.com.br';

const PATHS = {
  token:   '/auth/server-mtls/v2/token',
  saldo:   '/v1/fornecimento-saldos-contas/saldos',
  extrato: '/v1/fornecimento-extratos-contas/extratos',
};

// ─────────────────────────────────────────────
// Erro customizado para unidade não configurada
// Permite que o index.js retorne 503 em vez de 500.
// ─────────────────────────────────────────────
class UnitNotConfiguredError extends Error {
  constructor(unidade) {
    super(`Unidade "${unidade}" não está configurada no servidor.`);
    this.name = 'UnitNotConfiguredError';
  }
}

// ─────────────────────────────────────────────
// Configuração das unidades — lazy (sob demanda)
//
// Em vez de inicializar no boot do módulo (o que derrubava toda a API
// se uma variável estivesse ausente), cada unidade é construída apenas
// quando for realmente usada. Unidades sem variáveis ficam "desabilitadas"
// e retornam 503 ao ser chamadas.
// ─────────────────────────────────────────────
// Chave sentinela para cachear ausência de configuração.
// Evita re-leitura das env vars a cada chamada para unidades não configuradas.
const UNIT_DISABLED = Symbol('UNIT_DISABLED');
const unitConfigCache = {};  // { [prefix]: config | UNIT_DISABLED }

function getUnitConfig(prefix) {
  if (prefix in unitConfigCache) {
    const cached = unitConfigCache[prefix];
    return cached === UNIT_DISABLED ? null : cached;
  }

  const pfxBase64    = process.env[`CERTIFICADO_PFX_BASE64_${prefix}`];
  const pfxSenha     = process.env[`SENHA_CERTIFICADO_${prefix}`];
  const clientId     = process.env[`CLIENT_ID_${prefix}`];
  const clientSecret = process.env[`CLIENT_SECRET_${prefix}`];

  if (!pfxBase64 || !pfxSenha || !clientId || !clientSecret) {
    unitConfigCache[prefix] = UNIT_DISABLED; // cacheamos a ausência para não re-ler env vars
    return null;
  }

  const pfxBuffer = Buffer.from(pfxBase64, 'base64');

  const httpsAgent = new https.Agent({
    pfx:                pfxBuffer,
    passphrase:         pfxSenha,
    rejectUnauthorized: true,
    keepAlive:          true,
  });

  unitConfigCache[prefix] = { clientId, clientSecret, httpsAgent };
  return unitConfigCache[prefix];
}

// Unidades suportadas (chave = nome usado nas rotas)
const UNIT_PREFIX_MAP = {
  matriz: 'MATRIZ',
  filial: 'FILIAL',
};

// Retorna as unidades que possuem variáveis configuradas.
function getUnitsValid() {
  return Object.keys(UNIT_PREFIX_MAP).filter(
    (u) => getUnitConfig(UNIT_PREFIX_MAP[u]) !== null
  );
}

// ─────────────────────────────────────────────
// Cache de tokens — um por unidade
// Usa uma Promise em andamento para evitar race condition em serverless:
// invocações simultâneas reutilizam a mesma Promise em vez de disparar
// múltiplas requisições de token.
// ─────────────────────────────────────────────
const tokenCache    = {};   // { [unidade]: { token, expiresAt } }
const tokenPromises = {};   // { [unidade]: Promise<string> }

const TOKEN_REFRESH_MARGIN_MS = 2 * 60 * 1000;

function isCacheValid(unidade) {
  const c = tokenCache[unidade];
  return c?.token && c?.expiresAt && Date.now() < c.expiresAt - TOKEN_REFRESH_MARGIN_MS;
}

async function fetchNewToken(unidade) {
  const prefix = UNIT_PREFIX_MAP[unidade];
  const config = getUnitConfig(prefix);

  if (!config) {
    throw new UnitNotConfiguredError(unidade);
  }

  const { clientId, clientSecret, httpsAgent } = config;

  const body = new URLSearchParams({
    grant_type:    'client_credentials',
    client_id:     clientId,
    client_secret: clientSecret,
  });

  const response = await axios.post(
    `${BASE_URL}${PATHS.token}`,
    body.toString(),
    {
      httpsAgent,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      // Token é blocking — timeout curto para não estourar o budget total (10s + 20s = 30s).
      timeout: 10_000,
    }
  );

  const { access_token, expires_in } = response.data;

  if (!access_token) {
    throw new Error(`Token não retornado pelo Bradesco para a unidade "${unidade}".`);
  }

  tokenCache[unidade] = {
    token:     access_token,
    expiresAt: Date.now() + (expires_in ?? 3600) * 1000,
  };

  return access_token;
}

async function getAccessToken(unidade) {
  if (isCacheValid(unidade)) return tokenCache[unidade].token;

  // Reutiliza Promise em andamento — evita race condition em serverless.
  if (!tokenPromises[unidade]) {
    tokenPromises[unidade] = fetchNewToken(unidade).finally(() => {
      tokenPromises[unidade] = null;
    });
  }

  return tokenPromises[unidade];
}

// ─────────────────────────────────────────────
// Helper: monta instância Axios autenticada
// ─────────────────────────────────────────────
async function buildAxiosInstance(unidade) {
  const token  = await getAccessToken(unidade);
  const prefix = UNIT_PREFIX_MAP[unidade];
  const { httpsAgent } = getUnitConfig(prefix);

  return axios.create({
    baseURL:    BASE_URL,
    httpsAgent,
    timeout:    20_000,
    headers: {
      Authorization: `Bearer ${token}`,
      Accept:        'application/json',
    },
  });
}

// ─────────────────────────────────────────────
// Consulta de Saldo
// ─────────────────────────────────────────────
async function consultarSaldo(unidade, { agencia, conta, tipoOperacao }) {
  const api = await buildAxiosInstance(unidade);

  const params = { agencia, conta };
  if (tipoOperacao) params.tipoOperacao = tipoOperacao;

  const response = await api.get(PATHS.saldo, { params });
  return response.data;
}

// ─────────────────────────────────────────────
// Consulta de Extrato
// ─────────────────────────────────────────────
async function consultarExtrato(unidade, { agencia, conta, dataInicio, dataFim, tipo, tipoOperacao }) {
  const api = await buildAxiosInstance(unidade);

  const params = { agencia, conta, dataInicio, dataFim, tipo };
  if (tipoOperacao) params.tipoOperacao = tipoOperacao;

  const response = await api.get(PATHS.extrato, { params });
  return response.data;
}

// ─────────────────────────────────────────────
// Exports
// ─────────────────────────────────────────────
module.exports = {
  getUnitsValid,
  consultarSaldo,
  consultarExtrato,
  UnitNotConfiguredError,
};
