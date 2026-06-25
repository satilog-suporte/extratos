'use strict';

const axios = require('axios');
const https = require('https');

// ─────────────────────────────────────────────
// Configuração — lazy
// ─────────────────────────────────────────────
let _config = null;

function loadConfig() {
  if (_config) return _config;

  const clientId     = process.env.BB_CLIENT_ID;
  const clientSecret = process.env.BB_CLIENT_SECRET;
  const appKey       = process.env.BB_APP_KEY; // valor diferente em HML e PROD, mesmo nome de variável
  const baseUrl      = process.env.BB_BASE_URL;
  const tokenUrl     = process.env.BB_TOKEN_URL;
  const massaTeste   = process.env.BB_MASSA_TESTE;   // opcional — só em HML
  const bbEnv        = (process.env.BB_ENV ?? 'PROD').toUpperCase(); // HML | PROD
  const bbScope      = process.env.BB_SCOPE ?? 'extrato-info';

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

  // Proteção explícita: BB_MASSA_TESTE jamais pode ser usado em produção.
  if (massaTeste && bbEnv === 'PROD') {
    throw new Error(
      'BB_MASSA_TESTE está definido mas BB_ENV=PROD. ' +
      'O header x-br-com-bb-ipa-mciteste NÃO deve ser usado em produção. ' +
      'Remova BB_MASSA_TESTE ou ajuste BB_ENV=HML.'
    );
  }

  _config = { clientId, clientSecret, appKey, baseUrl, tokenUrl, massaTeste, bbEnv, bbScope };
  return _config;
}

// ─────────────────────────────────────────────
// Agente HTTPS com mTLS — OBRIGATÓRIO.
// Os hosts da API (ex.: extratos.mtls.api.bb.com.br) exigem certificado de
// cliente no próprio handshake TLS, antes de qualquer header HTTP ser lido.
// Sem isso a conexão é recusada na camada de TLS (ECONNRESET/socket hang up),
// não retorna um JSON de erro do BB.
//
// Forneça o certificado via UMA das opções abaixo (em base64, formato
// amigável a variáveis de ambiente em serverless/Vercel):
//
//   BB_MTLS_PFX_BASE64 + BB_MTLS_PASSPHRASE   → Certificado A1 .pfx (caso mais comum)
//   BB_MTLS_CERT_BASE64 + BB_MTLS_KEY_BASE64  → par .pem separado (cert + chave)
//
// Gerar o base64 a partir do arquivo original, ex.:
//   base64 -i certificado.pfx | tr -d '\n'
// ─────────────────────────────────────────────
let _httpsAgent = null;

function loadHttpsAgent() {
  if (_httpsAgent) return _httpsAgent;

  const pfxBase64  = process.env.BB_MTLS_PFX_BASE64;
  const certBase64 = process.env.BB_MTLS_CERT_BASE64;
  const keyBase64  = process.env.BB_MTLS_KEY_BASE64;
  const passphrase = process.env.BB_MTLS_PASSPHRASE;

  const agentOptions = { keepAlive: true, rejectUnauthorized: true };

  if (pfxBase64) {
    agentOptions.pfx = Buffer.from(pfxBase64, 'base64');
    if (passphrase) agentOptions.passphrase = passphrase;
  } else if (certBase64 && keyBase64) {
    agentOptions.cert = Buffer.from(certBase64, 'base64');
    agentOptions.key  = Buffer.from(keyBase64, 'base64');
    if (passphrase) agentOptions.passphrase = passphrase;
  } else {
    throw new Error(
      'Certificado mTLS ausente. Defina BB_MTLS_PFX_BASE64 (+ BB_MTLS_PASSPHRASE se houver senha) ' +
      'ou BB_MTLS_CERT_BASE64 + BB_MTLS_KEY_BASE64. A API de Extratos do BB exige mTLS em toda chamada.'
    );
  }

  _httpsAgent = new https.Agent(agentOptions);
  return _httpsAgent;
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
  const { clientId, clientSecret, tokenUrl, bbScope } = loadConfig();
  const httpsAgent = loadHttpsAgent();

  // O BB exige client_id/client_secret via HTTP Basic Auth no header
  // Authorization — NÃO como client_id/client_secret no corpo. Enviar no
  // corpo gera 400 "Identificador ou credencial inválidos".
  const basicAuth = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');

  const body = new URLSearchParams({
    grant_type: 'client_credentials',
    scope:      bbScope,
  });

  try {
    const response = await axios.post(tokenUrl, body.toString(), {
      httpsAgent,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Authorization:  `Basic ${basicAuth}`,
      },
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
  } catch (err) {
    // Enriquecer erro de autenticação com detalhes do BB
    if (err.response) {
      const { status, data } = err.response;
      throw new Error(
        `BB OAuth erro ${status} ao obter token: ${JSON.stringify(data)}`
      );
    }
    throw err;
  }
}

async function getAccessToken() {
  if (isCacheValid()) return tokenCache.token;

  if (!tokenPromise) {
    tokenPromise = fetchNewToken().finally(() => { tokenPromise = null; });
  }

  return tokenPromise;
}

// ─────────────────────────────────────────────
// Helpers de validação
// ─────────────────────────────────────────────

// BB exige agência/conta "sem DV, omitir zeros à esquerda" (ex.: 0297 → 297)
function stripLeadingZeros(value) {
  const n = parseInt(value, 10);
  if (Number.isNaN(n)) {
    throw new Error(`Valor inválido: "${value}" não é numérico.`);
  }
  return String(n);
}

// Normaliza a entrada para exatamente 8 dígitos (DDMMAAAA) antes de parsear.
// Aceita "01052025" (8 dígitos) e "1052025" (7 dígitos, sem zero inicial no dia).
// Lança erro se o tamanho não for 7 ou 8 dígitos, evitando interpretações ambíguas.
function parseDDMMAAAA(value) {
  const s = String(value).trim();

  if (!/^\d{7,8}$/.test(s)) {
    throw new Error(
      `Data inválida: "${value}". Esperado formato DDMMAAAA (7 ou 8 dígitos numéricos). ` +
      'Exemplo: "01052025" ou "1052025".'
    );
  }

  const padded = s.padStart(8, '0');
  const dia    = parseInt(padded.slice(0, 2), 10);
  const mes    = parseInt(padded.slice(2, 4), 10);
  const ano    = parseInt(padded.slice(4, 8), 10);

  const date = new Date(ano, mes - 1, dia);

  // Verifica que a data construída bate com os componentes (ex.: dia 32 seria inválido)
  if (
    date.getFullYear() !== ano ||
    date.getMonth()    !== mes - 1 ||
    date.getDate()     !== dia
  ) {
    throw new Error(
      `Data inválida: "${value}" não representa uma data de calendário real ` +
      `(dia=${dia}, mês=${mes}, ano=${ano}).`
    );
  }

  return date;
}

function validarParametros({ dataInicio, dataFim, tamanhoPagina }) {
  // Datas: ou as duas, ou nenhuma
  if ((dataInicio && !dataFim) || (!dataInicio && dataFim)) {
    throw new Error(
      'dataInicioSolicitacao e dataFimSolicitacao devem ser informados juntos (ou nenhum dos dois).'
    );
  }

  if (dataInicio && dataFim) {
    const inicio = parseDDMMAAAA(dataInicio);
    const fim    = parseDDMMAAAA(dataFim);
    const diffDias = (fim - inicio) / (1000 * 60 * 60 * 24);

    if (diffDias < 0) {
      throw new Error('dataFimSolicitacao não pode ser anterior a dataInicioSolicitacao.');
    }
    if (diffDias > 31) {
      throw new Error('Período máximo entre dataInicio e dataFim é de 31 dias.');
    }

    const anosAtras = (Date.now() - inicio.getTime()) / (1000 * 60 * 60 * 24 * 365.25);
    if (anosAtras > 5) {
      throw new Error('dataInicioSolicitacao não pode retroceder mais de 5 anos.');
    }
  }

  // v2: default 120, mínimo 50, máximo 120
  if (tamanhoPagina < 50 || tamanhoPagina > 120) {
    throw new Error('quantidadeRegistroPaginaSolicitacao deve estar entre 50 e 120.');
  }
}

// ─────────────────────────────────────────────
// Retry com backoff exponencial
// Só faz retry em falhas de rede/timeout e erros 5xx do servidor.
// Erros 4xx (cliente) NÃO são retentados — são definitivos.
// ─────────────────────────────────────────────
const RETRY_CONFIG = {
  tentativas:      2,          // tentativas adicionais após a primeira chamada
  delayInicialMs:  500,        // espera inicial entre tentativas
  fatorMultiplicador: 2,       // backoff exponencial (500ms → 1000ms)
};

function deveRetentar(err) {
  if (!err.response) return true;                          // sem resposta: rede/timeout
  return err.response.status >= 500;                      // erro do servidor BB
}

async function comRetry(fn) {
  let ultimoErro;
  let delayMs = RETRY_CONFIG.delayInicialMs;

  for (let tentativa = 0; tentativa <= RETRY_CONFIG.tentativas; tentativa++) {
    try {
      return await fn();
    } catch (err) {
      ultimoErro = err;

      if (tentativa < RETRY_CONFIG.tentativas && deveRetentar(err)) {
        await new Promise((resolve) => setTimeout(resolve, delayMs));
        delayMs *= RETRY_CONFIG.fatorMultiplicador;
        continue;
      }

      break;
    }
  }

  throw ultimoErro;
}

// ─────────────────────────────────────────────
// Tratamento de erros da API BB
// ─────────────────────────────────────────────
function traduzirErroBB(err, contexto = '') {
  if (!err.response) {
    // Falha de rede, timeout, ECONNRESET, mTLS rejeitado etc.
    const msg = contexto ? `[${contexto}] ` : '';
    throw new Error(`${msg}Falha de comunicação com a API BB: ${err.message}`);
  }

  const { status, data } = err.response;
  const detalhe = typeof data === 'object' ? JSON.stringify(data) : String(data);
  const prefixo = contexto ? `[${contexto}] ` : '';

  // Erros documentados pelo BB
  switch (status) {
    case 400:
      throw new Error(`${prefixo}BB API 400 Bad Request — parâmetros inválidos: ${detalhe}`);
    case 401:
      throw new Error(`${prefixo}BB API 401 Unauthorized — token inválido ou expirado: ${detalhe}`);
    case 403:
      throw new Error(`${prefixo}BB API 403 Forbidden — sem permissão para esta conta/agência: ${detalhe}`);
    case 404:
      throw new Error(`${prefixo}BB API 404 Not Found — conta não encontrada ou sem lançamentos no período: ${detalhe}`);
    case 429:
      throw new Error(`${prefixo}BB API 429 Too Many Requests — limite de requisições atingido: ${detalhe}`);
    default:
      throw new Error(`${prefixo}BB API erro ${status}: ${detalhe}`);
  }
}

// ─────────────────────────────────────────────
// Consulta de Extrato — Conta Corrente
// GET /conta-corrente/agencia/{agencia}/conta/{conta}
// ─────────────────────────────────────────────

/**
 * Consulta o extrato de conta corrente PJ no Banco do Brasil (v2).
 *
 * @param {object}  options
 * @param {string}  options.agencia       - Número da agência (sem DV; zeros à esquerda são removidos)
 * @param {string}  options.conta         - Número da conta (sem DV; zeros à esquerda são removidos)
 * @param {string}  [options.dataInicio]  - Data inicial DDMMAAAA (7 ou 8 dígitos). Se informada, dataFim é obrigatória.
 * @param {string}  [options.dataFim]     - Data final DDMMAAAA (7 ou 8 dígitos).
 * @param {number}  [options.numeroPagina=1]    - Página solicitada (padrão: 1)
 * @param {number}  [options.tamanhoPagina=120] - Registros por página (50–120; padrão: 120)
 *
 * @returns {Promise<object>} Payload de retorno da API BB, acrescido de:
 *   - `temProximaPagina` {boolean} — true se houver mais páginas disponíveis
 *
 * @throws {Error} Em caso de parâmetros inválidos, falha de rede ou erro da API BB.
 */
async function consultarExtratoBB({
  agencia,
  conta,
  dataInicio,
  dataFim,
  numeroPagina  = 1,
  tamanhoPagina = 120,
}) {
  const { appKey, baseUrl, massaTeste, bbEnv } = loadConfig();

  validarParametros({ dataInicio, dataFim, tamanhoPagina });

  const agenciaLimpa = stripLeadingZeros(agencia);
  const contaLimpa   = stripLeadingZeros(conta);

  const token      = await getAccessToken();
  const httpsAgent = loadHttpsAgent();

  // gw-dev-app-key vai como QUERY PARAM (confirmado na doc do recurso).
  // O valor muda entre HML/PROD via env var BB_APP_KEY; o nome do parâmetro
  // é o mesmo nos dois ambientes.
  const params = {
    'gw-dev-app-key':                    appKey,
    numeroPaginaSolicitacao:             numeroPagina,
    quantidadeRegistroPaginaSolicitacao: tamanhoPagina,
  };

  if (dataInicio) params.dataInicioSolicitacao = parseInt(dataInicio, 10);
  if (dataFim)    params.dataFimSolicitacao    = parseInt(dataFim, 10);

  const path = `/conta-corrente/agencia/${agenciaLimpa}/conta/${contaLimpa}`;

  const headers = {
    Authorization:  `Bearer ${token}`,
    Accept:         'application/json',
    'Content-Type': 'application/json',
  };

  // Obrigatório em HML; NUNCA deve ser enviado em PROD.
  // A guarda em loadConfig() já impede BB_MASSA_TESTE definido com BB_ENV=PROD.
  if (massaTeste && bbEnv === 'HML') {
    headers['x-br-com-bb-ipa-mciteste'] = massaTeste;
  }

  const contexto = `agencia=${agenciaLimpa} conta=${contaLimpa}`;

  const data = await comRetry(async () => {
    try {
      const response = await axios.get(`${baseUrl}${path}`, {
        httpsAgent,
        params,
        headers,
        timeout: 20_000,
      });
      return response.data;
    } catch (err) {
      traduzirErroBB(err, contexto); // sempre lança
    }
  });

  return {
    ...data,
    // Conveniência para o chamador saber se deve buscar a próxima página
    temProximaPagina: (data.numeroPaginaProximo ?? 0) > 0,
  };
}

// ─────────────────────────────────────────────
// Helper opcional: busca TODAS as páginas
// e retorna a lista de lançamentos consolidada.
//
// Use com cautela em períodos longos — pode gerar
// muitas requisições e atingir rate limit do BB.
// ─────────────────────────────────────────────

/**
 * Busca todas as páginas do extrato e retorna a lista de lançamentos completa.
 *
 * @param {object} options - Mesmos parâmetros de consultarExtratoBB (exceto numeroPagina)
 * @returns {Promise<object[]>} Array com todos os lançamentos do período
 */
async function consultarExtratoCompleto(options) {
  const lancamentos = [];
  let pagina = 1;

  do {
    const resultado = await consultarExtratoBB({ ...options, numeroPagina: pagina });
    lancamentos.push(...(resultado.listaLancamento ?? []));

    if (!resultado.temProximaPagina) break;
    pagina++;
  } while (true);

  return lancamentos;
}

module.exports = { consultarExtratoBB, consultarExtratoCompleto };
