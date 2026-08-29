// ============================================================
//  VILA REAL FUTSAL — API (Supabase Edge Function)
//
//  Reescrita do zero em Deno/TypeScript, porque o bundle da
//  função anterior ficou inacessível no painel do Supabase
//  ("Failed to retrieve function bundle") — tanto a visualização
//  quanto o download pararam de funcionar. Em vez de tentar
//  recuperar um código que nem o próprio Supabase consegue
//  entregar, esta versão foi escrita reaproveitando toda a
//  lógica de negócio já validada ao longo do projeto (a mesma
//  que rodava em Node/Express no Render), agora adaptada para
//  rodar como Edge Function.
//
//  Principal mudança em relação à versão anterior: FOTOS E
//  IMAGENS DE CONFIGURAÇÃO NÃO VÃO MAIS DENTRO DO JSON DO
//  ESTADO. Antes, cada foto de aluno (e as imagens de
//  personalização) viajavam em base64 dentro da resposta de
//  /api/state — e como o app busca esse estado periodicamente,
//  isso multiplicava o consumo de saída (egress) do Supabase
//  a cada poucos segundos, por usuário conectado. Agora elas
//  ficam no Supabase Storage (bucket "fotos") e o estado carrega
//  só a URL — o navegador baixa a imagem uma vez e guarda em
//  cache, em vez de rebaixar o arquivo inteiro toda hora.
// ============================================================

import express from 'npm:express@^5';
import bcrypt from 'npm:bcryptjs@^2';
import jwt from 'npm:jsonwebtoken@^9';
import pg from 'npm:pg@^8';
import { createClient } from 'npm:@supabase/supabase-js@2';

// ---------- Configuração / variáveis de ambiente ----------
// Todas configuradas como "secrets" da função (supabase secrets set).
// SUPABASE_URL e SUPABASE_DB_URL já vêm prontas automaticamente.
const DB_URL = Deno.env.get('SUPABASE_DB_URL') ?? Deno.env.get('DATABASE_URL');
const SUPABASE_URL = Deno.env.get('SUPABASE_URL')!;
const SERVICE_ROLE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
const JWT_SECRET = Deno.env.get('JWT_SECRET') || 'troque-este-segredo-nas-secrets';
const ADMIN_USER = Deno.env.get('ADMIN_USER') || 'admin';
const ADMIN_PASSWORD = Deno.env.get('ADMIN_PASSWORD') || 'admin123';
const ADMIN_EMAIL = Deno.env.get('ADMIN_EMAIL') || 'admin@vilarealfutsal.com';
const APP_URL = (Deno.env.get('APP_URL') || '').replace(/\/$/, '');
const SMTP_USER = Deno.env.get('SMTP_USER');
const SMTP_PASS = Deno.env.get('SMTP_PASS');
const FOTOS_BUCKET = 'fotos';

if (!DB_URL) {
  console.warn('⚠️  SUPABASE_DB_URL/DATABASE_URL não configurada — a função não vai conseguir acessar o banco.');
}
if (!APP_URL) {
  console.warn('⚠️  APP_URL não configurada — o link de redefinição de senha no e-mail pode ficar incorreto.');
}
if (!SMTP_USER || !SMTP_PASS) {
  console.warn('⚠️  SMTP_USER/SMTP_PASS não configuradas — o envio de e-mail de redefinição de senha não vai funcionar.');
}

// Cliente do Supabase com a chave de serviço — usado só para o Storage
// (upload/URL pública das fotos). Os dados relacionais continuam via SQL
// direto (pg), igual à versão anterior, para não precisar reescrever
// nenhuma consulta.
const supabaseAdmin = createClient(SUPABASE_URL, SERVICE_ROLE_KEY);

const pool = new pg.Pool({
  connectionString: DB_URL,
  ssl: { rejectUnauthorized: false },
  max: 5, // Edge Functions são de curta duração — poucas conexões evitam esgotar o limite do Postgres.
});

const DEFAULT_PERMISSIONS = {
  dashboard: true,
  alunos: true,
  presencas: true,
  carteirinhas: true,
  relatorios: true,
  notificacoes: true,
  backup: false,
  configuracoes: false,
  usuarios: false,
  personalizar: false,
  excluirAlunos: false,
  habilitarDesabilitar: false,
};

// ---------- Rate limiting (em memória) ----------
// Assim como no servidor anterior. Como Edge Functions podem reiniciar a
// qualquer momento (não há garantia de estado entre invocações "frias"),
// isso é uma proteção best-effort — não uma garantia matemática — mas
// cobre o caso comum de múltiplas tentativas na mesma invocação "quente".
const rateLimitBuckets = new Map<string, number[]>();
function rateLimit(windowMs: number, max: number) {
  return (req: express.Request, res: express.Response, next: express.NextFunction) => {
    const ip = (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() || req.ip || 'desconhecido';
    const key = ip + ':' + req.path;
    const now = Date.now();
    const bucket = rateLimitBuckets.get(key) || [];
    const fresh = bucket.filter((t) => now - t < windowMs);
    if (fresh.length >= max) {
      return res.status(429).json({ error: 'Muitas tentativas. Aguarde alguns minutos e tente novamente.' });
    }
    fresh.push(now);
    rateLimitBuckets.set(key, fresh);
    next();
  };
}

function sanitizeUser(row: any) {
  if (!row) return null;
  return {
    id: row.id,
    nome: row.nome,
    email: row.email,
    telefone: row.telefone || '',
    perfil: row.perfil,
    usuario: row.usuario,
    status: row.status,
    permissoes: { ...DEFAULT_PERMISSIONS, ...(row.permissoes || {}) },
    alunosVinculados: Array.isArray(row.alunos_vinculados) ? row.alunos_vinculados : [],
    criadoEm: row.criado_em,
    primeiroAcesso: row.primeiro_acesso,
  };
}

function signUser(user: any) {
  return jwt.sign({ sub: user.id }, JWT_SECRET, { expiresIn: '30d' });
}

// ---------- Autenticação (igual à versão anterior) ----------
async function auth(req: any, res: express.Response, next: express.NextFunction) {
  try {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Não autenticado' });
    const payload: any = jwt.verify(token, JWT_SECRET);
    const result = await pool.query('SELECT * FROM users WHERE id=$1', [payload.sub]);
    if (!result.rows[0]) return res.status(401).json({ error: 'Usuário não encontrado' });
    const user = result.rows[0];
    if (user.status !== 'aprovado') return res.status(403).json({ error: 'Acesso não autorizado' });
    req.dbUser = user;
    req.user = sanitizeUser(user);
    next();
  } catch (_err) {
    return res.status(401).json({ error: 'Sessão inválida ou expirada' });
  }
}

// ---------- Schema do banco (garante que as tabelas existem) ----------
// Roda uma vez por "instância quente" da função — equivalente ao
// ensureSchema() do servidor Express anterior, que rodava no startup.
let schemaGarantido = false;
async function ensureSchema() {
  if (schemaGarantido) return;
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      nome TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      telefone TEXT,
      perfil TEXT NOT NULL,
      usuario TEXT,
      senha_hash TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'aprovado',
      permissoes JSONB NOT NULL DEFAULT '{}',
      alunos_vinculados JSONB NOT NULL DEFAULT '[]',
      criado_em TIMESTAMPTZ NOT NULL DEFAULT now(),
      primeiro_acesso BOOLEAN NOT NULL DEFAULT true,
      reset_token_hash TEXT,
      reset_token_expires TIMESTAMPTZ
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS app_state (
      id INTEGER PRIMARY KEY DEFAULT 1,
      data JSONB NOT NULL DEFAULT '{}',
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
  await pool.query(`INSERT INTO app_state (id, data) VALUES (1, '{}') ON CONFLICT (id) DO NOTHING;`);

  // Como o banco já existe de antes (com dados reais), o CREATE TABLE IF NOT
  // EXISTS acima não adiciona colunas que talvez estejam faltando na tabela
  // atual. Estes ALTER TABLE cobrem isso com segurança, sem apagar nada.
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS telefone TEXT;`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token_hash TEXT;`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token_expires TIMESTAMPTZ;`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS permissoes JSONB NOT NULL DEFAULT '{}';`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS alunos_vinculados JSONB NOT NULL DEFAULT '[]';`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS primeiro_acesso BOOLEAN NOT NULL DEFAULT true;`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'aprovado';`);

  const adminExists = await pool.query('SELECT 1 FROM users WHERE id=$1', ['admin']);
  if (!adminExists.rows[0]) {
    const hash = await bcrypt.hash(ADMIN_PASSWORD, 12);
    await pool.query(
      `INSERT INTO users (id,nome,email,perfil,usuario,senha_hash,status,permissoes,alunos_vinculados,primeiro_acesso)
       VALUES ('admin',$1,$2,'Administrador',$3,$4,'aprovado',$5,'[]',false)`,
      ['Administrador', ADMIN_EMAIL, ADMIN_USER, hash, JSON.stringify({
        dashboard: true, alunos: true, presencas: true, carteirinhas: true, relatorios: true,
        notificacoes: true, backup: true, configuracoes: true, usuarios: true, personalizar: true,
        excluirAlunos: true, habilitarDesabilitar: true,
      })]
    );
    console.log('👑 Usuário administrador criado.');
  }
  schemaGarantido = true;
}

// ---------- Estado geral do app (app_state) ----------
const CAMPOS_APARENCIA_PUBLICOS = [
  'loginLogo', 'loginBg', 'loginPrimaryColor', 'loginTitleAccentColor', 'loginTextColor',
  'loginBoxBg', 'loginLogoSize', 'loginTitle', 'loginSubtitle', 'sidebarBrandTextColor',
  'cores', 'coresAvancadas', 'coresCarteirinha', 'carteirinhaFundo', 'carteirinhaLogo', 'botoes',
];

async function getState(perfilSolicitante?: string) {
  const state = await pool.query('SELECT data,updated_at FROM app_state WHERE id=1');
  const users = await pool.query('SELECT * FROM users ORDER BY criado_em ASC');
  const data = state.rows[0]?.data || {};
  data.usuarios = users.rows.map(sanitizeUser);
  data.solicitacoesPendentes = [];
  // A senha master só pode ser vista pelo administrador.
  if (perfilSolicitante !== 'Administrador' && data.config) {
    data.config = { ...data.config };
    delete data.config.senhaMaster;
  }
  return { data, updatedAt: state.rows[0]?.updated_at || null, userCount: users.rowCount };
}

async function upsertIncomingUsers(client: pg.PoolClient, incomingUsers: any) {
  if (!Array.isArray(incomingUsers)) return;
  for (const u of incomingUsers) {
    if (!u || !u.id || u.id === 'admin') continue;
    const existing = await client.query('SELECT * FROM users WHERE id=$1', [u.id]);
    const perms = { ...DEFAULT_PERMISSIONS, ...(u.permissoes || {}) };
    const linked = Array.isArray(u.alunosVinculados) ? u.alunosVinculados : [];
    if (existing.rows[0]) {
      if (u.senha) {
        const hash = await bcrypt.hash(String(u.senha), 12);
        await client.query(
          `UPDATE users SET nome=$2,email=$3,perfil=$4,usuario=$5,status=$6,permissoes=$7,alunos_vinculados=$8,primeiro_acesso=$9,senha_hash=$10,telefone=$11 WHERE id=$1`,
          [u.id, u.nome, u.email, u.perfil || 'Professor', u.usuario, u.status || 'aprovado', JSON.stringify(perms), JSON.stringify(linked), u.primeiroAcesso !== false, hash, u.telefone || null]
        );
      } else {
        await client.query(
          `UPDATE users SET nome=$2,email=$3,perfil=$4,usuario=$5,status=$6,permissoes=$7,alunos_vinculados=$8,primeiro_acesso=$9,telefone=$10 WHERE id=$1`,
          [u.id, u.nome, u.email, u.perfil || 'Professor', u.usuario, u.status || 'aprovado', JSON.stringify(perms), JSON.stringify(linked), u.primeiroAcesso !== false, u.telefone || null]
        );
      }
    } else if (u.senha && u.email && u.usuario) {
      const hash = await bcrypt.hash(String(u.senha), 12);
      await client.query(
        `INSERT INTO users (id,nome,email,perfil,usuario,senha_hash,status,permissoes,alunos_vinculados,criado_em,primeiro_acesso,telefone)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT DO NOTHING`,
        [u.id, u.nome, u.email, u.perfil || 'Professor', u.usuario, hash, u.status || 'aprovado', JSON.stringify(perms), JSON.stringify(linked), u.criadoEm || new Date().toISOString(), u.primeiroAcesso !== false, u.telefone || null]
      );
    }
  }
}

// Mesma proteção da versão anterior: um usuário comum só pode alterar os
// campos de leitura (lidaPor / ocultaPara) de itens que já existiam — nunca
// criar item novo, alterar conteúdo, ou apagar de verdade.
function validarSomenteCamposDeLeitura(incomingList: any, listaAtual: any, idUsuario: string, campos: string[]) {
  const atual = Array.isArray(listaAtual) ? listaAtual : [];
  if (!Array.isArray(incomingList) || incomingList.length !== atual.length) return atual;

  const mapaAtual = new Map(atual.map((n: any) => [n && n.id, n]));
  const valido = incomingList.every((item: any) => {
    if (!item || !mapaAtual.has(item.id)) return false;
    const original: any = mapaAtual.get(item.id);
    const restoIncoming: any = { ...item };
    const restoOriginal: any = { ...original };
    campos.forEach((c) => { delete restoIncoming[c]; delete restoOriginal[c]; });
    if (JSON.stringify(restoIncoming) !== JSON.stringify(restoOriginal)) return false;

    return campos.every((campo) => {
      const setIncoming = new Set(Array.isArray(item[campo]) ? item[campo] : []);
      const setOriginal = new Set(Array.isArray(original[campo]) ? original[campo] : []);
      for (const id of setOriginal) if (!setIncoming.has(id)) return false;
      for (const id of setIncoming) if (!setOriginal.has(id) && id !== idUsuario) return false;
      return true;
    });
  });

  return valido ? incomingList : atual;
}

// ---------- Storage: fotos e imagens (a correção do egress) ----------
// Recebe uma imagem em base64 (data URL), decodifica e sobe pro bucket do
// Storage, devolvendo uma URL pública curta — em vez de guardar o arquivo
// inteiro dentro do JSON do estado, que era baixado de novo a cada
// sincronização por cada usuário conectado.
async function uploadFotoBase64(dataUrl: string, pastaPrefixo: string): Promise<string> {
  const match = /^data:(image\/[a-zA-Z+]+);base64,(.+)$/.exec(dataUrl);
  if (!match) throw new Error('Formato de imagem inválido (esperado data URL base64)');
  const mime = match[1];
  const base64 = match[2];
  const extensao = mime.split('/')[1]?.replace('jpeg', 'jpg') || 'jpg';
  const bytes = Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
  const nomeArquivo = `${pastaPrefixo}/${Date.now()}-${Math.random().toString(36).slice(2, 8)}.${extensao}`;

  const { error } = await supabaseAdmin.storage.from(FOTOS_BUCKET).upload(nomeArquivo, bytes, {
    contentType: mime,
    upsert: false,
  });
  if (error) throw new Error('Falha ao subir imagem: ' + error.message);

  const { data } = supabaseAdmin.storage.from(FOTOS_BUCKET).getPublicUrl(nomeArquivo);
  return data.publicUrl;
}

// Se o campo já for uma URL (não um data URL base64), devolve como está —
// permite que o front chame o mesmo endpoint de forma idempotente.
async function normalizarImagemParaUrl(valor: string | undefined | null, pastaPrefixo: string): Promise<string> {
  if (!valor) return '';
  if (valor.startsWith('data:image/')) return await uploadFotoBase64(valor, pastaPrefixo);
  return valor;
}

// ---------- E-mail (recuperação de senha) ----------
// Envia via a API HTTP do Gmail/SMTP usando fetch direto (evita depender de
// uma biblioteca de SMTP via socket TCP cru, que tem suporte mais instável
// em ambientes de Edge Function). Usa o serviço de e-mail transacional da
// Resend, compatível com Deno via fetch simples — só precisa de uma
// RESEND_API_KEY nas secrets. Se preferir continuar com Gmail/SMTP, dá pra
// trocar esta função por nodemailer via "npm:nodemailer" — funciona no
// Deno, mas prefira testar antes de usar em produção.
const RESEND_API_KEY = Deno.env.get('RESEND_API_KEY');
const RESEND_FROM = Deno.env.get('RESEND_FROM') || 'Vila Real Futsal <onboarding@resend.dev>';

async function enviarEmail({ to, subject, html, text }: { to: string; subject: string; html: string; text: string }) {
  if (!RESEND_API_KEY) {
    console.warn('⚠️  RESEND_API_KEY não configurada — e-mail não enviado (log apenas):', { to, subject });
    return;
  }
  const resp = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${RESEND_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ from: RESEND_FROM, to: [to], subject, html, text }),
  });
  if (!resp.ok) {
    const errBody = await resp.text();
    throw new Error('Falha ao enviar e-mail: ' + errBody);
  }
}

// ============================================================
//  APP EXPRESS
// ============================================================
const app = express();
app.use(express.json({ limit: '3mb' }));

// CORS — o front (index.html) fica num domínio diferente do Supabase,
// então toda resposta precisa liberar a origem explicitamente.
app.use((req, res, next) => {
  res.set('Access-Control-Allow-Origin', '*');
  res.set('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  res.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(204).end();
  next();
});

// Garante o schema antes de qualquer rota (roda uma vez por instância).
app.use(async (_req, _res, next) => {
  try { await ensureSchema(); next(); } catch (e) { next(e); }
});

// Cabeçalhos de segurança (iguais à versão anterior).
app.use((_req, res, next) => {
  res.set('X-Content-Type-Options', 'nosniff');
  res.set('X-Frame-Options', 'DENY');
  res.set('Referrer-Policy', 'no-referrer');
  next();
});

// ---------- Autenticação ----------
app.post('/api/auth/login', rateLimit(15 * 60 * 1000, 15), async (req, res) => {
  try {
    const { usuario, senha } = req.body || {};
    if (!usuario || !senha) return res.status(400).json({ error: 'Usuário e senha obrigatórios' });

    const result = await pool.query(
      'SELECT * FROM users WHERE usuario=$1 OR email=$1',
      [String(usuario).trim()]
    );
    const row = result.rows[0];
    if (!row) return res.status(401).json({ error: 'Usuário ou senha inválidos' });
    if (row.status !== 'aprovado') return res.status(403).json({ error: 'Seu acesso não está autorizado' });

    const senhaOk = await bcrypt.compare(String(senha), row.senha_hash);
    if (!senhaOk) return res.status(401).json({ error: 'Usuário ou senha inválidos' });

    const user = sanitizeUser(row);
    const state = await getState(row.perfil);
    res.json({ token: signUser(user), user, state: state.data, serverUserCount: state.userCount });
  } catch (e) {
    console.error('Erro em login:', e);
    res.status(500).json({ error: 'Erro ao entrar' });
  }
});

app.post('/api/auth/register', rateLimit(15 * 60 * 1000, 10), async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { nome, email, senha } = req.body || {};
    const perfil = 'Pai';
    if (!nome || !email || !senha) throw new Error('Preencha todos os campos');
    if (String(senha).length < 6) throw new Error('A senha deve ter no mínimo 6 caracteres');
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email))) throw new Error('E-mail inválido');

    const existing = await client.query('SELECT 1 FROM users WHERE email=$1', [email]);
    if (existing.rows[0]) throw new Error('Este e-mail já está cadastrado');

    const count = await client.query('SELECT COUNT(*)::int AS n FROM users');
    const numero = String(count.rows[0].n + 1).padStart(4, '0');
    const usuarioGerado = 'user' + numero;
    const id = 'user_' + Date.now();
    const hash = await bcrypt.hash(String(senha), 12);

    await client.query(
      `INSERT INTO users (id,nome,email,perfil,usuario,senha_hash,status,permissoes,alunos_vinculados,primeiro_acesso)
       VALUES ($1,$2,$3,$4,$5,$6,'aprovado',$7,'[]',true)`,
      [id, nome, email, perfil, usuarioGerado, hash, JSON.stringify(DEFAULT_PERMISSIONS)]
    );

    // Notificação para o admin + mensagem de boas-vindas para o novo usuário.
    const stateAtual = await client.query('SELECT data FROM app_state WHERE id=1');
    const atual = stateAtual.rows[0]?.data || {};
    const notificacoes = Array.isArray(atual.notificacoes) ? atual.notificacoes : [];
    notificacoes.push({
      id: 'notif_' + Date.now(),
      tipo: 'novo_cadastro',
      usuarioNome: 'Sistema',
      mensagem: `Novo cadastro: ${nome} (${email}) — Pai/Responsável`,
      data: new Date().toISOString(),
    });
    atual.notificacoes = notificacoes;

    const mensagens = Array.isArray(atual.mensagensInternas) ? atual.mensagensInternas : [];
    mensagens.push({
      id: 'msg_' + Date.now(),
      remetenteId: 'admin',
      remetenteNome: 'Vila Real Futsal',
      geral: false,
      destinatarioId: id,
      destinatarioNome: nome,
      mensagem: 'Bem-vindo(a) ao Vila Real Futsal! 🏆⚽ Cadastre seu(s) aluno(s) para começar.',
      data: new Date().toISOString(),
      lidaPor: [],
    });
    atual.mensagensInternas = mensagens;

    await client.query('UPDATE app_state SET data=$1, updated_at=now() WHERE id=1', [JSON.stringify(atual)]);

    await client.query('COMMIT');
    res.json({ ok: true, usuario: usuarioGerado });
  } catch (e: any) {
    await client.query('ROLLBACK');
    res.status(400).json({ error: e.message || 'Não foi possível concluir o cadastro' });
  } finally {
    client.release();
  }
});

app.post('/api/auth/forgot-password', rateLimit(15 * 60 * 1000, 8), async (req: any, res: any) => {
  const respostaGenerica = { ok: true, message: 'Se este e-mail estiver cadastrado, enviamos um link de redefinição.' };
  try {
    const { email } = req.body || {};
    if (!email) return res.json(respostaGenerica);

    const result = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
    const user = result.rows[0];
    if (!user || user.status !== 'aprovado') return res.json(respostaGenerica);

    const token = crypto.randomUUID().replace(/-/g, '') + crypto.randomUUID().replace(/-/g, '');
    const tokenHash = await bcrypt.hash(token, 10);
    const expira = new Date(Date.now() + 30 * 60 * 1000);

    await pool.query('UPDATE users SET reset_token_hash=$1, reset_token_expires=$2 WHERE id=$3', [tokenHash, expira.toISOString(), user.id]);

    const link = `${APP_URL}/?resetToken=${token}&uid=${user.id}`;
    const nomeSeguro = String(user.nome || '').replace(/[<>&"]/g, (c) => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;' }[c] as string));
    await enviarEmail({
      to: user.email,
      subject: 'Redefinição de senha — Vila Real Futsal',
      html: `<p>Olá, ${nomeSeguro}.</p>
             <p>Recebemos uma solicitação para redefinir sua senha no sistema Vila Real Futsal.</p>
             <p><a href="${link}" style="background:#d4a020;color:#0f1b2d;padding:10px 20px;border-radius:8px;text-decoration:none;font-weight:bold;">Redefinir minha senha</a></p>
             <p>Ou copie e cole este link no navegador:<br>${link}</p>
             <p>Este link é válido por 30 minutos. Se você não solicitou esta redefinição, ignore este e-mail.</p>`,
      text: `Redefina sua senha acessando: ${link} (válido por 30 minutos)`,
    });

    res.json(respostaGenerica);
  } catch (e) {
    console.error('Erro em forgot-password:', e);
    res.json(respostaGenerica); // nunca revela se o e-mail existe ou não
  }
});

app.post('/api/auth/reset-password', rateLimit(15 * 60 * 1000, 10), async (req: any, res: any) => {
  try {
    const { uid, token, novaSenha } = req.body || {};
    if (!uid || !token || !novaSenha) return res.status(400).json({ error: 'Dados incompletos' });
    if (String(novaSenha).length < 6) return res.status(400).json({ error: 'Senha deve ter no mínimo 6 caracteres' });

    const result = await pool.query('SELECT * FROM users WHERE id=$1', [uid]);
    const user = result.rows[0];
    if (!user || !user.reset_token_hash || !user.reset_token_expires) {
      return res.status(400).json({ error: 'Link inválido ou expirado' });
    }
    if (new Date(user.reset_token_expires) < new Date()) {
      return res.status(400).json({ error: 'Link expirado. Solicite um novo.' });
    }
    const tokenOk = await bcrypt.compare(String(token), user.reset_token_hash);
    if (!tokenOk) return res.status(400).json({ error: 'Link inválido' });

    const hash = await bcrypt.hash(String(novaSenha), 12);
    await pool.query('UPDATE users SET senha_hash=$1, reset_token_hash=NULL, reset_token_expires=NULL WHERE id=$2', [hash, uid]);

    res.json({ ok: true, message: 'Senha redefinida com sucesso. Você já pode fazer login.' });
  } catch (e) {
    console.error('Erro em reset-password:', e);
    res.status(500).json({ error: 'Não foi possível redefinir a senha' });
  }
});

app.get('/api/me', auth, async (req: any, res: any) => res.json({ user: req.user }));

app.get('/api/public/branding', async (_req: any, res: any) => {
  try {
    const state = await pool.query('SELECT data FROM app_state WHERE id=1');
    const config = state.rows[0]?.data?.config || {};
    const aparencia: any = {};
    CAMPOS_APARENCIA_PUBLICOS.forEach((campo) => {
      if (config[campo] !== undefined) aparencia[campo] = config[campo];
    });
    res.json({ config: aparencia });
  } catch (e) {
    console.error('Erro ao carregar aparência pública:', e);
    res.status(500).json({ error: 'Erro ao carregar aparência' });
  }
});

// Atualiza os dados do administrador principal (fora da sincronização geral).
app.put('/api/auth/admin-profile', auth, async (req: any, res: any) => {
  if (req.dbUser.id !== 'admin' || req.dbUser.perfil !== 'Administrador') {
    return res.status(403).json({ error: 'Apenas o administrador principal' });
  }
  try {
    const { nome, email, telefone, novaSenha } = req.body || {};
    if (!nome || !email) return res.status(400).json({ error: 'Nome e e-mail obrigatórios' });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email))) return res.status(400).json({ error: 'E-mail inválido' });
    if (novaSenha && String(novaSenha).length < 6) return res.status(400).json({ error: 'Senha deve ter no mínimo 6 caracteres' });

    if (novaSenha) {
      const hash = await bcrypt.hash(String(novaSenha), 12);
      await pool.query('UPDATE users SET nome=$1,email=$2,telefone=$3,senha_hash=$4 WHERE id=$5', [nome, email, telefone || null, hash, 'admin']);
    } else {
      await pool.query('UPDATE users SET nome=$1,email=$2,telefone=$3 WHERE id=$4', [nome, email, telefone || null, 'admin']);
    }
    const result = await pool.query('SELECT * FROM users WHERE id=$1', ['admin']);
    res.json({ ok: true, user: sanitizeUser(result.rows[0]) });
  } catch (e: any) {
    if (e.code === '23505') return res.status(409).json({ error: 'Este e-mail já está em uso' });
    console.error('Erro ao atualizar perfil do administrador:', e);
    res.status(500).json({ error: 'Não foi possível atualizar o perfil' });
  }
});

// Pai/Responsável se autovincula a um aluno que ele mesmo cadastrou.
app.post('/api/auth/vincular-aluno', auth, async (req: any, res: any) => {
  try {
    if (req.dbUser.perfil !== 'Pai') {
      return res.status(403).json({ error: 'Apenas Pais/Responsáveis podem se autovincular a um aluno' });
    }
    const { alunoId } = req.body || {};
    if (!alunoId) return res.status(400).json({ error: 'Informe o aluno' });

    const state = await pool.query('SELECT data FROM app_state WHERE id=1');
    const alunos = state.rows[0]?.data?.alunos || [];
    if (!alunos.some((a: any) => a && a.id === alunoId)) {
      return res.status(404).json({ error: 'Aluno não encontrado' });
    }

    const vinculadosAtuais = Array.isArray(req.dbUser.alunos_vinculados) ? req.dbUser.alunos_vinculados : [];
    if (vinculadosAtuais.includes(alunoId)) {
      return res.json({ ok: true, alunosVinculados: vinculadosAtuais });
    }
    if (vinculadosAtuais.length >= 2) {
      return res.status(400).json({ error: 'Limite de 2 alunos por Pai/Responsável excedido' });
    }

    const novaLista = [...vinculadosAtuais, alunoId];
    await pool.query('UPDATE users SET alunos_vinculados=$1 WHERE id=$2', [JSON.stringify(novaLista), req.dbUser.id]);
    res.json({ ok: true, alunosVinculados: novaLista });
  } catch (e) {
    console.error('Erro ao autovincular aluno:', e);
    res.status(500).json({ error: 'Não foi possível vincular o aluno' });
  }
});

// Habilitar/desabilitar usuário — admin, ou Professor com a permissão concedida.
app.post('/api/users/:id/toggle-status', auth, async (req: any, res: any) => {
  try {
    const podeUsar = req.dbUser.perfil === 'Administrador' ||
      (req.dbUser.perfil === 'Professor' && req.dbUser.permissoes && req.dbUser.permissoes.habilitarDesabilitar === true);
    if (!podeUsar) return res.status(403).json({ error: 'Você não tem permissão para habilitar/desabilitar usuários' });
    if (req.params.id === 'admin') return res.status(400).json({ error: 'Não é possível desabilitar o administrador principal' });

    const result = await pool.query('SELECT * FROM users WHERE id=$1', [req.params.id]);
    const alvo = result.rows[0];
    if (!alvo) return res.status(404).json({ error: 'Usuário não encontrado' });

    const novoStatus = alvo.status === 'aprovado' ? 'desabilitado' : 'aprovado';
    await pool.query('UPDATE users SET status=$1 WHERE id=$2', [novoStatus, req.params.id]);
    res.json({ ok: true, status: novoStatus });
  } catch (e) {
    console.error('Erro ao habilitar/desabilitar usuário:', e);
    res.status(500).json({ error: 'Não foi possível alterar o status do usuário' });
  }
});

app.delete('/api/users/:id', auth, async (req: any, res: any) => {
  if (req.dbUser.perfil !== 'Administrador') return res.status(403).json({ error: 'Apenas administradores' });
  if (req.params.id === 'admin') return res.status(400).json({ error: 'Não é possível excluir o administrador' });
  await pool.query('DELETE FROM users WHERE id=$1', [req.params.id]);
  res.json({ ok: true });
});

// ---------- NOVO: upload de foto/imagem para o Storage ----------
// Recebe { imagemBase64, tipo } e devolve { url }. "tipo" define a pasta:
// 'aluno' | 'logo' | 'fundo-carteirinha' | 'logo-login' etc.
app.post('/api/upload-imagem', auth, async (req: any, res: any) => {
  try {
    const { imagemBase64, tipo } = req.body || {};
    if (!imagemBase64) return res.status(400).json({ error: 'Envie a imagem em base64' });
    const pasta = (tipo || 'geral').replace(/[^a-z0-9-]/gi, '');
    const url = await uploadFotoBase64(imagemBase64, pasta);
    res.json({ ok: true, url });
  } catch (e: any) {
    console.error('Erro ao subir imagem:', e);
    res.status(500).json({ error: e.message || 'Não foi possível subir a imagem' });
  }
});

// ---------- Estado geral ----------
app.get('/api/state', auth, async (req: any, res: any) => {
  try { res.json(await getState(req.dbUser.perfil)); }
  catch (e) { console.error(e); res.status(500).json({ error: 'Erro ao carregar dados' }); }
});

app.put('/api/state', auth, async (req: any, res: any) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const incoming = req.body?.data;
    if (!incoming || typeof incoming !== 'object') throw new Error('Dados inválidos');

    const perfil = req.dbUser.perfil;
    const isAdminUser = perfil === 'Administrador';
    const isStaff = isAdminUser || perfil === 'Professor';

    if (!isAdminUser) {
      delete incoming.usuarios;
      if (incoming.config) delete incoming.config.senhaMaster;
    }

    const stateAtualRes = await client.query('SELECT data FROM app_state WHERE id=1');
    const dataAtual = stateAtualRes.rows[0]?.data || {};

    if (!isStaff) {
      incoming.config = dataAtual.config;
      incoming.presencas = dataAtual.presencas;
      incoming.notificacoes = validarSomenteCamposDeLeitura(incoming.notificacoes, dataAtual.notificacoes, req.dbUser.id, ['ocultaPara']);
      incoming.mensagensInternas = validarSomenteCamposDeLeitura(incoming.mensagensInternas, dataAtual.mensagensInternas, req.dbUser.id, ['lidaPor', 'ocultaPara']);

      if (Array.isArray(incoming.alunos)) {
        const alunosAtuais = dataAtual.alunos || [];
        const idsAlunosExistentes = new Set(alunosAtuais.map((a: any) => a && a.id));
        const novosAlunos = incoming.alunos.filter((a: any) => a && a.id && !idsAlunosExistentes.has(a.id));
        const jaVinculados = Array.isArray(req.dbUser.alunos_vinculados) ? req.dbUser.alunos_vinculados.length : 0;
        if (jaVinculados + novosAlunos.length > 2) throw new Error('Limite de 2 alunos por Pai/Responsável excedido');
      }
    }

    // Fotos/imagens que ainda chegarem em base64 (ex: um cliente antigo em
    // cache) são automaticamente subidas para o Storage aqui — assim nunca
    // fica nada pesado gravado dentro do JSON do estado, mesmo que o front
    // esqueça de chamar /api/upload-imagem antes.
    if (Array.isArray(incoming.alunos)) {
      for (const a of incoming.alunos) {
        if (a && typeof a.foto === 'string' && a.foto.startsWith('data:image/')) {
          a.foto = await uploadFotoBase64(a.foto, 'aluno');
        }
      }
    }
    if (isStaff && incoming.config) {
      for (const campo of ['loginLogo', 'carteirinhaFundo', 'carteirinhaLogo']) {
        if (typeof incoming.config[campo] === 'string' && incoming.config[campo].startsWith('data:image/')) {
          incoming.config[campo] = await uploadFotoBase64(incoming.config[campo], 'config');
        }
      }
    }

    await upsertIncomingUsers(client, incoming.usuarios);
    if (isAdminUser && Array.isArray(incoming.usuarios)) {
      // nada extra a fazer — upsertIncomingUsers já cobre a criação/edição
    }

    const safeState = { ...incoming };
    delete safeState.usuarios; // usuários vivem na tabela users, não no JSON
    delete safeState.solicitacoesPendentes;

    await client.query('UPDATE app_state SET data=$1, updated_at=now() WHERE id=1', [JSON.stringify(safeState)]);
    await client.query('COMMIT');

    res.json(await getState(perfil));
  } catch (e: any) {
    await client.query('ROLLBACK');
    console.error('Erro ao salvar estado:', e);
    res.status(400).json({ error: e.message || 'Erro ao salvar dados' });
  } finally {
    client.release();
  }
});

app.use('/api', (_req: any, res: any) => res.status(404).json({ error: 'Rota não encontrada' }));

// Contrato de entrada de uma Edge Function do Supabase: um objeto default
// com "fetch". O Express, quando ligado numa porta, também atende esse
// contrato no ambiente do Supabase — mesmo padrão usado nos exemplos
// oficiais de Edge Function com Express.
app.listen(8000, () => console.log('🏆 Vila Real Futsal API rodando (Edge Function)'));
