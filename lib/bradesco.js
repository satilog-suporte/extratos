'use strict';

const axios = require('axios');
const https = require('https');
const qs = require('querystring');

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
// Configuração das unidades
// Lê as variáveis de ambiente uma única vez no
// carregamento do módulo para não repetir lógica.
// ─────────────────────────────────────────────
function buildUnitConfig(prefix) {
  const pfxBase64 = process.env[`CERTIFICADO_PFX_BASE64_${prefix}`];
  const pfxSenha  = process.env[`SENHA_CERTIFICADO_${prefix}`];
  const clientId  = process.env[`CLIENT_ID_${prefix}`];
  const clientSecret = process.env[`CLIENT_SECRET_${prefix}`];

  if (!pfxBase64 || !pfxSenha || !clientId || !clientSecret) {
    throw new Error(
      `Variáveis de ambiente ausentes para a unidade "${prefix}". ` +
      `Verifique: CERTIFICADO_PFX_BASE64_${prefix}, SENHA_CERTIFICADO_${prefix}, ` +
      `CLIENT_ID_${prefix}, CLIENT_SECRET_${prefix}.`
    );
  }

  const pfxBuffer = Buffer.from(pfxBase64, 'base64');

  // Cada unidade tem seu próprio https.Agent com o certificado injetado.
  const httpsAgent = new https.Agent({
    pfx:        pfxBuffer,
    passphrase: pfxSenha,
    // Rejeita certificados inválidos em produção.
    rejectUnauthorized: true,
  });

  return { clientId, clientSecret, httpsAgent };
}

// Inicializa as duas unidades. Se alguma variável estiver faltando,
// a exceção é lançada no boot do módulo — falha rápida e visível.
const UNITS = {
  matriz:  buildUnitConfig('MATRIZ'),
  filial:  buildUnitConfig('FILIAL'),
};

// ─────────────────────────────────────────────
// Cache em memória por unidade
// Estrutura: { token: string, expiresAt: number (ms epoch) }
// Em Serverless cada worker mantém seu próprio heap;
// o cache funciona bem para invocações "quentes" e evita
// a geração excessiva de tokens que o Bradesco penaliza.
// ─────────────────────────────────────────────
const tokenCache = {
  matriz: null,
  filial: null,
};

// Margem de 2 minutos antes da expiração para renovar proativamente.
const TOKEN_REFRESH_MARGIN_MS = 2 * 60 * 1000;

function isCacheValid(cached) {
  if (!cached || !cached.token || !cached.expiresAt) return false;
  return Date.now() < cached.expiresAt - TOKEN_REFRESH_MARGIN_MS;
}

// ─────────────────────────────────────────────
// Autenticação OAuth 2.0 (client_credentials)
// ─────────────────────────────────────────────
async function getAccessToken(unidade) {
  // Retorna do cache se ainda válido.
  if (isCacheValid(tokenCache[unidade])) {
    return tokenCache[unidade].token;
  }

  const { clientId, clientSecret, httpsAgent } = UNITS[unidade];

  const response = await axios.post(
    `${BASE_URL}${PATHS.token}`,
    qs.stringify({
      grant_type:    'client_credentials',
      client_id:     clientId,
      client_secret: clientSecret,
    }),
    {
      httpsAgent,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      timeout: 15_000,
    }
  );

  const { access_token, expires_in } = response.data;

  if (!access_token) {
    throw new Error(`Token não retornado pelo Bradesco para a unidade "${unidade}".`);
  }

  // expires_in vem em segundos (normalmente 3600 = 1h).
  const expiresAt = Date.now() + (expires_in ?? 3600) * 1000;

  tokenCache[unidade] = { token: access_token, expiresAt };

  return access_token;
}

// ─────────────────────────────────────────────
// Helper: monta instância Axios autenticada
// ─────────────────────────────────────────────
async function buildAxiosInstance(unidade) {
  const token = await getAccessToken(unidade);
  const { httpsAgent } = UNITS[unidade];

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
  UNITS_VALID: Object.keys(UNITS),   // ['matriz', 'filial']
  consultarSaldo,
  consultarExtrato,
};
