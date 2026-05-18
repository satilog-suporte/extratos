'use strict';

require('dotenv').config();

const express = require('express');
const cors    = require('cors');

const { UNITS_VALID, consultarSaldo, consultarExtrato } = require('./lib/bradesco');

const app = express();

// ─────────────────────────────────────────────
// Middleware global
// ─────────────────────────────────────────────
app.use(cors());
app.use(express.json());

// ─────────────────────────────────────────────
// Middleware de Autenticação da nossa API
//
// O frontend deve enviar a chave em um dos formatos:
//   Header:  x-api-key: <chave>
//   Header:  Authorization: Bearer <chave>
//
// A chave é comparada com a variável FRONTEND_API_KEY.
// ─────────────────────────────────────────────
function authMiddleware(req, res, next) {
  const apiKey = process.env.FRONTEND_API_KEY;

  if (!apiKey) {
    // Configuração ausente no servidor — não deve chegar em produção.
    return res.status(500).json({
      error: 'Configuração interna inválida: FRONTEND_API_KEY não definida no servidor.',
    });
  }

  // Extrai a chave enviada pelo cliente.
  const fromHeader  = req.headers['x-api-key'];
  const authHeader  = req.headers['authorization'] ?? '';
  const fromBearer  = authHeader.startsWith('Bearer ')
    ? authHeader.slice(7).trim()
    : null;

  const receivedKey = fromHeader || fromBearer;

  if (!receivedKey || receivedKey !== apiKey) {
    return res.status(401).json({
      error: 'Não autorizado. Envie a chave correta no header "x-api-key" ou "Authorization: Bearer <chave>".',
    });
  }

  next();
}

// Aplica o middleware em todas as rotas /api/*
app.use('/api', authMiddleware);

// ─────────────────────────────────────────────
// Helper: valida e normaliza parâmetros comuns
// ─────────────────────────────────────────────
function validarUnidade(unidade, res) {
  const u = unidade?.toLowerCase();
  if (!UNITS_VALID.includes(u)) {
    res.status(400).json({
      error: `Unidade inválida: "${unidade}". Use "matriz" ou "filial".`,
    });
    return null;
  }
  return u;
}

function validarAgenciaConta(agencia, conta, res) {
  if (!agencia || !conta) {
    res.status(400).json({
      error: 'Os parâmetros "agencia" e "conta" são obrigatórios.',
    });
    return false;
  }

  const agenciaStr = String(agencia).trim();
  const contaStr   = String(conta).trim();

  if (!/^\d{1,4}$/.test(agenciaStr)) {
    res.status(400).json({ error: 'Agência inválida. Deve conter até 4 dígitos numéricos.' });
    return false;
  }

  if (!/^\d{1,7}$/.test(contaStr)) {
    res.status(400).json({ error: 'Conta inválida. Deve conter até 7 dígitos numéricos.' });
    return false;
  }

  return true;
}

// Garante 7 dígitos com zeros à esquerda, conforme exigência da API.
function padConta(conta) {
  return String(conta).trim().padStart(7, '0');
}

// ─────────────────────────────────────────────
// Helper: trata erros do Axios de forma padronizada
// ─────────────────────────────────────────────
function handleAxiosError(err, res) {
  console.error('[BFF] Erro na chamada ao Bradesco:', err.message);

  if (err.response) {
    // O Bradesco respondeu com um status de erro (4xx / 5xx).
    return res.status(err.response.status).json({
      error:   'Erro retornado pelo Bradesco.',
      details: err.response.data,
    });
  }

  if (err.request) {
    // A requisição foi feita mas não houve resposta (timeout, rede).
    return res.status(504).json({
      error: 'O Bradesco não respondeu dentro do tempo limite. Tente novamente.',
    });
  }

  // Erro de configuração / lógica interna.
  return res.status(500).json({
    error:   'Erro interno do servidor.',
    message: err.message,
  });
}

// ─────────────────────────────────────────────
// GET /api/:unidade/saldo
//
// Query params:
//   agencia      (obrigatório) — até 4 dígitos
//   conta        (obrigatório) — até 7 dígitos (será padded)
//   tipoOperacao (opcional)    — 1 ou 2
//
// Exemplo:
//   GET /api/matriz/saldo?agencia=1234&conta=30524
//   GET /api/filial/saldo?agencia=5678&conta=0012345&tipoOperacao=2
// ─────────────────────────────────────────────
app.get('/api/:unidade/saldo', async (req, res) => {
  const unidade = validarUnidade(req.params.unidade, res);
  if (!unidade) return;

  const { agencia, conta, tipoOperacao } = req.query;

  if (!validarAgenciaConta(agencia, conta, res)) return;

  // Validação opcional de tipoOperacao.
  if (tipoOperacao && !['1', '2'].includes(String(tipoOperacao))) {
    return res.status(400).json({ error: 'tipoOperacao deve ser "1" ou "2".' });
  }

  try {
    const dados = await consultarSaldo(unidade, {
      agencia:      String(agencia).trim(),
      conta:        padConta(conta),
      tipoOperacao: tipoOperacao || undefined,
    });

    return res.status(200).json(dados);
  } catch (err) {
    return handleAxiosError(err, res);
  }
});

// ─────────────────────────────────────────────
// GET /api/:unidade/extrato
//
// Query params:
//   agencia      (obrigatório) — até 4 dígitos
//   conta        (obrigatório) — até 7 dígitos (será padded)
//   dataInicio   (obrigatório) — formato DDMMAAAA
//   dataFim      (obrigatório) — formato DDMMAAAA
//   tipo         (obrigatório) — "cc" ou "cp"
//   tipoOperacao (opcional)    — 1 ou 2
//
// Exemplo:
//   GET /api/matriz/extrato?agencia=1234&conta=30524&dataInicio=01052025&dataFim=31052025&tipo=cc
// ─────────────────────────────────────────────
app.get('/api/:unidade/extrato', async (req, res) => {
  const unidade = validarUnidade(req.params.unidade, res);
  if (!unidade) return;

  const { agencia, conta, dataInicio, dataFim, tipo, tipoOperacao } = req.query;

  if (!validarAgenciaConta(agencia, conta, res)) return;

  // Valida datas.
  if (!dataInicio || !dataFim) {
    return res.status(400).json({ error: 'Os parâmetros "dataInicio" e "dataFim" são obrigatórios (formato DDMMAAAA).' });
  }

  if (!/^\d{8}$/.test(dataInicio) || !/^\d{8}$/.test(dataFim)) {
    return res.status(400).json({ error: 'Formato de data inválido. Use DDMMAAAA (ex: 01052025).' });
  }

  // Valida tipo de conta.
  if (!tipo) {
    return res.status(400).json({ error: 'O parâmetro "tipo" é obrigatório. Use "cc" (corrente) ou "cp" (poupança).' });
  }

  const tipoNorm = String(tipo).toLowerCase();
  if (!['cc', 'cp'].includes(tipoNorm)) {
    return res.status(400).json({ error: 'Parâmetro "tipo" inválido. Use "cc" (corrente) ou "cp" (poupança).' });
  }

  // Validação opcional de tipoOperacao.
  if (tipoOperacao && !['1', '2'].includes(String(tipoOperacao))) {
    return res.status(400).json({ error: 'tipoOperacao deve ser "1" ou "2".' });
  }

  try {
    const dados = await consultarExtrato(unidade, {
      agencia:      String(agencia).trim(),
      conta:        padConta(conta),
      dataInicio:   String(dataInicio).trim(),
      dataFim:      String(dataFim).trim(),
      tipo:         tipoNorm,
      tipoOperacao: tipoOperacao || undefined,
    });

    return res.status(200).json(dados);
  } catch (err) {
    return handleAxiosError(err, res);
  }
});

// ─────────────────────────────────────────────
// Health-check (rota pública, sem auth)
// ─────────────────────────────────────────────
app.get('/api/health', (req, res) => {
  res.status(200).json({ status: 'ok', ts: new Date().toISOString() });
});

// ─────────────────────────────────────────────
// 404 para rotas não mapeadas
// ─────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ error: `Rota não encontrada: ${req.method} ${req.path}` });
});

// ─────────────────────────────────────────────
// Export para Vercel Serverless + start local
// ─────────────────────────────────────────────
module.exports = app;

if (require.main === module) {
  const PORT = process.env.PORT || 3001;
  app.listen(PORT, () => {
    console.log(`[BFF] Servidor rodando em http://localhost:${PORT}`);
  });
}
