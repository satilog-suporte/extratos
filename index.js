'use strict';

require('dotenv').config();

const crypto = require('crypto');

const express      = require('express');
const cors         = require('cors');
const helmet       = require('helmet');
const rateLimit    = require('express-rate-limit');

const { getUnitsValid, consultarSaldo, consultarExtrato, UnitNotConfiguredError } = require('./lib/bradesco');
const { consultarExtratoBB }                                                      = require('./lib/bb');

const app = express();

// ─────────────────────────────────────────────
// Logger estruturado (JSON)
// Facilita busca e análise de logs no painel da Vercel em produção.
// ─────────────────────────────────────────────
function log(level, message, extra = {}) {
  console[level === 'error' ? 'error' : 'log'](
    JSON.stringify({ level, ts: new Date().toISOString(), message, ...extra })
  );
}

// ─────────────────────────────────────────────
// Middleware global
// ─────────────────────────────────────────────

// CSP explícito: false desabilita o header (esta API só serve JSON, não HTML).
app.use(helmet({ contentSecurityPolicy: false }));

// CORS restrito ao domínio do frontend configurado em ALLOWED_ORIGIN.
const allowedOrigin = process.env.ALLOWED_ORIGIN;
app.use(cors(
  allowedOrigin
    ? { origin: allowedOrigin }
    : undefined
));

app.use(express.json({ limit: '10kb' }));

// ─────────────────────────────────────────────
// Correlation ID — injeta um ID único por request para rastrear
// logs entre index.js, lib/ e chamadas ao banco.
// O cliente pode enviar seu próprio ID via x-request-id; senão geramos um.
// ─────────────────────────────────────────────
app.use((req, res, next) => {
  req.correlationId = (req.headers['x-request-id'] || crypto.randomUUID()).slice(0, 64);
  res.set('x-request-id', req.correlationId);
  next();
});

// Rate limiter — protege as rotas de API contra abuso.
const apiLimiter = rateLimit({
  windowMs: 60_000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Muitas requisições. Tente novamente em instantes.' },
});

// ─────────────────────────────────────────────
// Middleware de Autenticação da nossa API
//
// O frontend deve enviar a chave em um dos formatos:
//   Header:  x-api-key: <chave>
//   Header:  Authorization: Bearer <chave>
// ─────────────────────────────────────────────
function authMiddleware(req, res, next) {
  const apiKey = process.env.FRONTEND_API_KEY;

  if (!apiKey) {
    return res.status(500).json({
      error: 'Configuração interna inválida: FRONTEND_API_KEY não definida no servidor.',
    });
  }

  const fromHeader = req.headers['x-api-key'];
  const authHeader = req.headers['authorization'] ?? '';
  const fromBearer = authHeader.startsWith('Bearer ')
    ? authHeader.slice(7).trim()
    : null;

  const receivedKey = fromHeader || fromBearer;

  // Comparação timing-safe para evitar ataques de enumeração por timing.
  const keysMatch = receivedKey &&
    receivedKey.length === apiKey.length &&
    crypto.timingSafeEqual(Buffer.from(receivedKey), Buffer.from(apiKey));

  if (!keysMatch) {
    return res.status(401).json({
      error: 'Não autorizado. Envie a chave correta no header "x-api-key" ou "Authorization: Bearer <chave>".',
    });
  }

  next();
}

// Health-check público — deve ficar ANTES do middleware de autenticação.
app.get('/api/health', (req, res) => {
  res.status(200).json({ status: 'ok', ts: new Date().toISOString() });
});

// Rate limiter — aplicado a todas as rotas /api/* exceto health check.
// Nota: dentro de app.use('/api', ...) o Express já normaliza req.path,
// então /api//health chega como req.path === '/health' — o check abaixo é seguro.
app.use('/api', (req, res, next) => {
  if (req.path === '/health') return next();
  return apiLimiter(req, res, next);
});

app.use('/api', authMiddleware);

// Timeout por request — cancela a resposta se o handler demorar mais que 28s.
// Fica abaixo do limite máximo da Vercel (30s), dando margem para fechar
// a conexão de forma limpa antes do hard-kill da plataforma.
app.use((req, res, next) => {
  const TIMEOUT_MS = 28_000;
  const timer = setTimeout(() => {
    if (!res.headersSent) {
      log('error', 'Request timeout', { correlationId: req.correlationId, path: req.path });
      res.status(504).json({ error: 'O servidor não conseguiu responder a tempo. Tente novamente.' });
    }
  }, TIMEOUT_MS);
  res.on('finish', () => clearTimeout(timer));
  res.on('close',  () => clearTimeout(timer));
  next();
});

// ─────────────────────────────────────────────
// Helpers compartilhados
// ─────────────────────────────────────────────

function validarUnidade(unidade, validList, banco, res) {
  const u = unidade?.toLowerCase();
  if (!validList.includes(u)) {
    res.status(400).json({
      error: `Unidade inválida para ${banco}: "${unidade}". Use: ${validList.join(', ')}.`,
    });
    return null;
  }
  return u;
}

function validarAgenciaConta(agencia, conta, res) {
  if (!agencia || !conta) {
    res.status(400).json({ error: 'Os parâmetros "agencia" e "conta" são obrigatórios.' });
    return false;
  }

  if (!/^\d{1,4}$/.test(String(agencia).trim())) {
    res.status(400).json({ error: 'Agência inválida. Deve conter até 4 dígitos numéricos.' });
    return false;
  }

  if (!/^\d+$/.test(String(conta).trim())) {
    res.status(400).json({ error: 'Conta inválida. Deve conter apenas dígitos numéricos.' });
    return false;
  }

  return true;
}

/**
 * Valida e faz parse de uma data no formato DDMMAAAA.
 * Retorna um objeto Date se válida, ou null se inválida.
 */
function parseDDMMAAAA(s) {
  if (!/^\d{8}$/.test(s)) return null;

  const d = parseInt(s.slice(0, 2), 10);
  const m = parseInt(s.slice(2, 4), 10);
  const y = parseInt(s.slice(4), 10);

  const dt = new Date(y, m - 1, d);

  // Verifica se a data "virou" (ex: dia 32 vira dia 1 do mês seguinte)
  if (dt.getFullYear() !== y || dt.getMonth() !== m - 1 || dt.getDate() !== d) {
    return null;
  }

  return dt;
}

/**
 * Valida dataInicio e dataFim:
 *   - Formato DDMMAAAA
 *   - Datas reais (sem dias/meses impossíveis)
 *   - dataFim >= dataInicio
 *   - Período máximo em dias (0 = sem limite)
 */
function validarDatas(dataInicio, dataFim, res, maxDias = 0) {
  if (!dataInicio || !dataFim) {
    res.status(400).json({
      error: 'Os parâmetros "dataInicio" e "dataFim" são obrigatórios (formato DDMMAAAA).',
    });
    return null;
  }

  const dtInicio = parseDDMMAAAA(dataInicio);
  const dtFim    = parseDDMMAAAA(dataFim);

  if (!dtInicio) {
    res.status(400).json({ error: `"dataInicio" inválida: "${dataInicio}". Use o formato DDMMAAAA com uma data real.` });
    return null;
  }

  if (!dtFim) {
    res.status(400).json({ error: `"dataFim" inválida: "${dataFim}". Use o formato DDMMAAAA com uma data real.` });
    return null;
  }

  if (dtFim < dtInicio) {
    res.status(400).json({ error: '"dataFim" deve ser igual ou posterior a "dataInicio".' });
    return null;
  }

  if (maxDias > 0) {
    const diffDias = Math.floor((dtFim - dtInicio) / 86_400_000);
    if (diffDias > maxDias) {
      res.status(400).json({ error: `Período máximo permitido: ${maxDias} dias.` });
      return null;
    }
  }

  return { dtInicio, dtFim };
}

function padConta(conta) {
  return String(conta).trim().padStart(7, '0');
}

function handleAxiosError(err, res, req) {
  // Unidade Bradesco sem variáveis configuradas → 503
  if (err instanceof UnitNotConfiguredError) {
    log('error', err.message, { correlationId: req?.correlationId });
    return res.status(503).json({
      error: 'Esta unidade não está disponível no momento. Verifique a configuração do servidor.',
    });
  }

  log('error', 'Erro na chamada ao banco', { correlationId: req?.correlationId, stack: err.stack });

  if (err.response) {
    // Logamos apenas o status HTTP — nunca o payload (pode conter PII financeira: saldos, transações).
    log('error', 'Resposta de erro do banco', { correlationId: req?.correlationId, httpStatus: err.response.status });
    return res.status(err.response.status).json({
      error: 'Erro retornado pelo banco.',
    });
  }

  if (err.request) {
    return res.status(504).json({
      error: 'O banco não respondeu dentro do tempo limite. Tente novamente.',
    });
  }

  return res.status(500).json({
    error: 'Erro interno do servidor.',
  });
}

// ─────────────────────────────────────────────
// Handlers reutilizáveis — elimina duplicação entre
// rotas novas (/bradesco/:unidade) e legadas (/:unidade)
// ─────────────────────────────────────────────

async function handleBradescoSaldo(req, res) {
  const unidades = getUnitsValid();
  const unidade  = validarUnidade(req.params.unidade, unidades, 'Bradesco', res);
  if (!unidade) return;

  const { agencia, conta, tipoOperacao } = req.query;

  if (!validarAgenciaConta(agencia, conta, res)) return;

  if (tipoOperacao && !['1', '2'].includes(String(tipoOperacao).trim())) {
    return res.status(400).json({ error: 'tipoOperacao deve ser "1" ou "2".' });
  }

  try {
    const dados = await consultarSaldo(unidade, {
      agencia:      String(agencia).trim(),
      conta:        padConta(conta),
      tipoOperacao: tipoOperacao ? String(tipoOperacao).trim() : undefined,
    });
    return res.status(200).json(dados);
  } catch (err) {
    return handleAxiosError(err, res, req);
  }
}

async function handleBradescoExtrato(req, res) {
  const unidades = getUnitsValid();
  const unidade  = validarUnidade(req.params.unidade, unidades, 'Bradesco', res);
  if (!unidade) return;

  const { agencia, conta, dataInicio, dataFim, tipo, tipoOperacao } = req.query;

  if (!validarAgenciaConta(agencia, conta, res)) return;
  if (!validarDatas(dataInicio, dataFim, res)) return;

  if (!tipo) {
    return res.status(400).json({ error: 'O parâmetro "tipo" é obrigatório. Use "cc" (corrente) ou "cp" (poupança).' });
  }

  const tipoNorm = String(tipo).toLowerCase();
  if (!['cc', 'cp'].includes(tipoNorm)) {
    return res.status(400).json({ error: 'Parâmetro "tipo" inválido. Use "cc" ou "cp".' });
  }

  if (tipoOperacao && !['1', '2'].includes(String(tipoOperacao).trim())) {
    return res.status(400).json({ error: 'tipoOperacao deve ser "1" ou "2".' });
  }

  try {
    const dados = await consultarExtrato(unidade, {
      agencia:      String(agencia).trim(),
      conta:        padConta(conta),
      dataInicio:   String(dataInicio).trim(),
      dataFim:      String(dataFim).trim(),
      tipo:         tipoNorm,
      tipoOperacao: tipoOperacao ? String(tipoOperacao).trim() : undefined,
    });
    return res.status(200).json(dados);
  } catch (err) {
    return handleAxiosError(err, res, req);
  }
}

// ═════════════════════════════════════════════
// BRADESCO
// ═════════════════════════════════════════════

/**
 * GET /api/bradesco/:unidade/saldo
 *
 * Query params:
 *   agencia      (obrigatório) — até 4 dígitos
 *   conta        (obrigatório) — até 7 dígitos (será padded)
 *   tipoOperacao (opcional)    — "1" ou "2"
 *
 * Exemplo:
 *   GET /api/bradesco/matriz/saldo?agencia=1234&conta=30524
 */
app.get('/api/bradesco/:unidade/saldo', handleBradescoSaldo);

/**
 * GET /api/bradesco/:unidade/extrato
 *
 * Query params:
 *   agencia      (obrigatório) — até 4 dígitos
 *   conta        (obrigatório) — até 7 dígitos (será padded)
 *   dataInicio   (obrigatório) — DDMMAAAA
 *   dataFim      (obrigatório) — DDMMAAAA
 *   tipo         (obrigatório) — "cc" ou "cp"
 *   tipoOperacao (opcional)    — "1" ou "2"
 *
 * Exemplo:
 *   GET /api/bradesco/matriz/extrato?agencia=1234&conta=30524&dataInicio=01052025&dataFim=31052025&tipo=cc
 */
app.get('/api/bradesco/:unidade/extrato', handleBradescoExtrato);

// ═════════════════════════════════════════════
// BANCO DO BRASIL
// (registrado antes das rotas legadas /api/:unidade/* para evitar conflito)
// ═════════════════════════════════════════════

/**
 * GET /api/bb/extrato
 *
 * Consulta extrato de conta corrente via API BB (Open Finance).
 * Apenas conta da Matriz — credenciais únicas via BB_CLIENT_ID / BB_CLIENT_SECRET / BB_APP_KEY.
 *
 * Query params:
 *   agencia      (obrigatório) — até 4 dígitos, sem DV
 *   conta        (obrigatório) — dígitos numéricos, sem DV
 *   dataInicio   (opcional*)  — DDMMAAAA  ex: 01052025
 *   dataFim      (opcional*)  — DDMMAAAA  ex: 31052025
 *   pagina       (opcional)   — número da página, padrão 1
 *   pageSize     (opcional)   — registros por página, 50–200, padrão 200
 *
 * * Se uma das datas for informada, a outra é obrigatória.
 *   Sem datas → retorna os últimos 30 dias.
 *   Período máximo entre dataInicio e dataFim: 31 dias.
 *
 * Exemplos:
 *   GET /api/bb/extrato?agencia=1505&conta=1348
 *   GET /api/bb/extrato?agencia=1505&conta=1348&dataInicio=01052025&dataFim=31052025
 *   GET /api/bb/extrato?agencia=1505&conta=1348&dataInicio=01052025&dataFim=31052025&pagina=2&pageSize=100
 */
app.get('/api/bb/extrato', async (req, res) => {
  const { agencia, conta, dataInicio, dataFim, pagina, pageSize } = req.query;

  if (!validarAgenciaConta(agencia, conta, res)) return;

  // Se UMA das datas for informada, AMBAS são obrigatórias.
  if ((dataInicio && !dataFim) || (!dataInicio && dataFim)) {
    return res.status(400).json({
      error: 'Se "dataInicio" for informado, "dataFim" também é obrigatório — e vice-versa.',
    });
  }

  // Valida datas com período máximo de 31 dias (exigência da API BB).
  if (dataInicio && dataFim) {
    if (!validarDatas(dataInicio, dataFim, res, 31)) return;
  }

  // Valida paginação.
  const numeroPagina = pagina ? Number(pagina) : 1;
  if (!Number.isInteger(numeroPagina) || numeroPagina < 1) {
    return res.status(400).json({ error: 'O parâmetro "pagina" deve ser um inteiro >= 1.' });
  }

  const tamanhoPagina = pageSize ? Number(pageSize) : 200;
  if (!Number.isInteger(tamanhoPagina) || tamanhoPagina < 50 || tamanhoPagina > 200) {
    return res.status(400).json({ error: 'O parâmetro "pageSize" deve ser um inteiro entre 50 e 200.' });
  }

  try {
    const dados = await consultarExtratoBB({
      agencia:      String(agencia).trim(),
      conta:        String(conta).trim(),
      dataInicio:   dataInicio ? String(dataInicio).trim() : undefined,
      dataFim:      dataFim    ? String(dataFim).trim()    : undefined,
      numeroPagina,
      tamanhoPagina,
    });

    return res.status(200).json(dados);
  } catch (err) {
    return handleAxiosError(err, res, req);
  }
});

// ═════════════════════════════════════════════
// Rotas legadas Bradesco sem prefixo /bradesco
// (mantidas para retrocompatibilidade; ficam APÓS /api/bb/* para não conflitar)
// ═════════════════════════════════════════════
app.get('/api/:unidade/saldo', (req, res, next) => {
  res.set('Deprecation', 'true');
  res.set('Link', '</api/bradesco/' + req.params.unidade + '/saldo>; rel="successor-version"');
  return handleBradescoSaldo(req, res, next);
});

app.get('/api/:unidade/extrato', (req, res, next) => {
  res.set('Deprecation', 'true');
  res.set('Link', '</api/bradesco/' + req.params.unidade + '/extrato>; rel="successor-version"');
  return handleBradescoExtrato(req, res, next);
});

// ═════════════════════════════════════════════
// 404
// ═════════════════════════════════════════════
app.use((req, res) => {
  res.status(404).json({ error: `Rota não encontrada: ${req.method} ${req.path}` });
});

// ═════════════════════════════════════════════
// Global error handler — captura erros assíncronos não tratados
// que escaparam do try/catch nas rotas (ex: bugs de middleware).
// ═════════════════════════════════════════════
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  log('error', 'Erro não tratado capturado pelo global handler', {
    method: req.method,
    path:   req.path,
    stack:  err.stack,
  });
  res.status(500).json({ error: 'Erro interno do servidor.' });
});

// ═════════════════════════════════════════════
// Export Vercel + start local
// ═════════════════════════════════════════════
module.exports = app;

if (require.main === module) {
  const PORT = process.env.PORT || 3001;
  app.listen(PORT, () => {
    log('info', `Servidor rodando`, { port: PORT });
  });
}
