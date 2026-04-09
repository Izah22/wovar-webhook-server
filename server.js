/**
 * server.js — Wovar Dashboard Backend
 *
 * Twee verantwoordelijkheden:
 *   1. POST /webhook/netsuite/salesorder  — ontvangt minimale webhook van NetSuite
 *                                           en pusht toast via SSE naar dashboard
 *   2. GET  /api/totals                   — haalt kanaaltotalen op via NetSuite
 *                                           Saved Search REST API en geeft ze terug
 *                                           aan het dashboard
 */

import express from 'express';
import crypto  from 'crypto';
import cors    from 'cors';

const app  = express();
const PORT = process.env.PORT || 3001;

// ─── Config ───────────────────────────────────────────────────────────────────
const WEBHOOK_SECRET = process.env.WOVAR_WEBHOOK_SECRET || 'verander-mij';
const JWT_SECRET     = process.env.JWT_SECRET           || 'wovar-jwt-secret';

// NetSuite Saved Search config
// Saved Search ID: bijv. 'customsearch_wovar_channel_totals'
const NS_ACCOUNT     = process.env.NS_ACCOUNT_ID;        // bijv. 7498142
const NS_SEARCH_ID   = process.env.NS_SAVED_SEARCH_ID;   // bijv. customsearch_wovar_channel_totals
const NS_TOKEN_KEY   = process.env.NS_TOKEN_KEY;         // TBA token key
const NS_TOKEN_SECRET= process.env.NS_TOKEN_SECRET;      // TBA token secret
const NS_CONSUMER_KEY= process.env.NS_CONSUMER_KEY;      // TBA consumer key
const NS_CONSUMER_SEC= process.env.NS_CONSUMER_SECRET;   // TBA consumer secret

// ─── Gebruikers ───────────────────────────────────────────────────────────────
const parseUsers = () => {
  const raw = process.env.WOVAR_USERS || 'admin:wovar2024,warehouse:wovar2024';
  return Object.fromEntries(raw.split(',').map(e => { const [u,p]=e.split(':'); return [u.trim(),p.trim()]; }));
};
const USERS = parseUsers();

// ─── Simpele JWT ──────────────────────────────────────────────────────────────
const b64  = s => Buffer.from(s).toString('base64url');
const signJWT = p => { const h=b64(JSON.stringify({alg:'HS256',typ:'JWT'})); const b=b64(JSON.stringify({...p,iat:Math.floor(Date.now()/1000),exp:Math.floor(Date.now()/1000)+86400})); return `${h}.${b}.${crypto.createHmac('sha256',JWT_SECRET).update(`${h}.${b}`).digest('base64url')}`; };
const verifyJWT = t => { try { const [h,b,s]=t.split('.'); if(s!==crypto.createHmac('sha256',JWT_SECRET).update(`${h}.${b}`).digest('base64url')) return null; const p=JSON.parse(Buffer.from(b,'base64url').toString()); return p.exp<Math.floor(Date.now()/1000)?null:p; } catch{return null;} };

// ─── Auth middleware ──────────────────────────────────────────────────────────
const requireAuth = (req,res,next) => {
  const token=(req.headers.authorization||'').replace('Bearer ','') || req.query.token;
  const p=token?verifyJWT(token):null;
  if(!p) return res.status(401).json({error:'Niet ingelogd'});
  req.user=p; next();
};

// ─── NetSuite OAuth1 helper ───────────────────────────────────────────────────
// Genereert een Authorization header voor NetSuite TBA (Token Based Auth)
const nsOAuthHeader = (url, method = 'GET') => {
  const nonce     = crypto.randomBytes(16).toString('hex');
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const params = {
    oauth_consumer_key:     NS_CONSUMER_KEY,
    oauth_nonce:            nonce,
    oauth_signature_method: 'HMAC-SHA256',
    oauth_timestamp:        timestamp,
    oauth_token:            NS_TOKEN_KEY,
    oauth_version:          '1.0',
  };
  const base = `${method}&${encodeURIComponent(url)}&${encodeURIComponent(
    Object.keys(params).sort().map(k=>`${k}=${encodeURIComponent(params[k])}`).join('&')
  )}`;
  const sigKey = `${encodeURIComponent(NS_CONSUMER_SEC)}&${encodeURIComponent(NS_TOKEN_SECRET)}`;
  params.oauth_signature = crypto.createHmac('sha256', sigKey).update(base).digest('base64');
  const header = 'OAuth realm="' + NS_ACCOUNT + '",' +
    Object.entries(params).map(([k,v])=>`${k}="${encodeURIComponent(v)}"`).join(',');
  return header;
};

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(cors({ origin: process.env.FRONTEND_URL || '*' }));
app.use(express.json());

// ─── POST /auth/login ─────────────────────────────────────────────────────────
app.post('/auth/login', (req,res) => {
  const {username,password}=req.body||{};
  if(!username||!password) return res.status(400).json({error:'Vul beide velden in'});
  const exp=USERS[username.toLowerCase()];
  if(!exp||exp!==password) return res.status(401).json({error:'Gebruikersnaam of wachtwoord onjuist'});
  res.json({token:signJWT({username:username.toLowerCase()}),username:username.toLowerCase()});
});

// ─── SSE clients ──────────────────────────────────────────────────────────────
const clients = new Set();

// ─── GET /events — SSE (beveiligd) ───────────────────────────────────────────
app.get('/events', requireAuth, (req,res) => {
  res.setHeader('Content-Type','text/event-stream');
  res.setHeader('Cache-Control','no-cache');
  res.setHeader('Connection','keep-alive');
  res.flushHeaders();
  const client={id:Date.now(),res};
  clients.add(client);
  const hb=setInterval(()=>res.write(': heartbeat\n\n'),30000);
  req.on('close',()=>{ clearInterval(hb); clients.delete(client); });
});

// ─── POST /webhook/netsuite/salesorder ───────────────────────────────────────
app.post('/webhook/netsuite/salesorder', express.raw({type:'*/*'}), (req,res) => {
  const raw  = Buffer.isBuffer(req.body) ? req.body.toString('utf8') : (typeof req.body === 'object' ? JSON.stringify(req.body) : String(req.body || ''));
  const sig  = req.headers['x-wovar-signature'];

  // Verifieer signature als aanwezig
  if (sig) {
    const exp = `sha256=${crypto.createHmac('sha256',WEBHOOK_SECRET).update(raw).digest('hex')}`;
    try { if(!crypto.timingSafeEqual(Buffer.from(sig),Buffer.from(exp))) return res.status(401).json({error:'Invalid signature'}); }
    catch { return res.status(401).json({error:'Invalid signature'}); }
  }

  let event;
  try { event=JSON.parse(raw); } catch { return res.status(400).json({error:'Invalid JSON'}); }

  const {toast} = event;
  console.log(`✅ Nieuwe SO: ${toast?.tranId} | ${toast?.customer} | €${toast?.amount} | ${toast?.channel}`);

  // Push alleen de toast data naar verbonden dashboard clients
  const msg = JSON.stringify({ type: 'new_order', toast });
  clients.forEach(c => c.res.write(`data: ${msg}\n\n`));

  res.status(200).json({ received: true });
});

// ─── GET /api/totals — haalt Saved Search op uit NetSuite ────────────────────
// Het dashboard pollt dit endpoint elke 60 seconden voor actuele kanaaltotalen.
//
// Verwacht formaat van de Saved Search (kolommen):
//   - Groepering:  custbody_wovar_channel  (of jouw kanaalnaam veld)
//   - Formule:     COUNT(internalid)        → als "orders"
//   - Formule:     SUM(netamount)           → als "omzet"
//
app.get('/api/totals', requireAuth, async (req,res) => {
  // Als NetSuite credentials niet zijn ingesteld → geef lege array terug
  if (!NS_ACCOUNT || !NS_SEARCH_ID || !NS_TOKEN_KEY) {
    return res.json({ totals: [], source: 'unconfigured' });
  }

  try {
    const url = `https://${NS_ACCOUNT}.suitetalk.api.netsuite.com/services/rest/query/v1/suiteql`;

    // SuiteQL query — past de veldnamen aan naar jouw Saved Search structuur
    // Vervang 'custbody_wovar_channel' door jouw kanaalnaam veld
    const query = `
      SELECT
        CASE
          WHEN custbody_wovar_channel = 'Webshop'        THEN 'Webshop'
          WHEN custbody_wovar_channel = 'Marketplaces'   THEN 'Marketplaces'
          WHEN custbody_wovar_channel = 'B2B Handmatig'  THEN 'B2B Handmatig'
          WHEN custbody_wovar_channel = 'B2B Webshop'    THEN 'B2B Webshop'
          WHEN custbody_wovar_channel = 'Gadero'         THEN 'Gadero'
          ELSE 'Overig'
        END AS channel,
        COUNT(id)            AS orders,
        SUM(netamount)       AS omzet
      FROM transaction
      WHERE type = 'SalesOrd'
        AND trandate = TODAY()
      GROUP BY custbody_wovar_channel
      ORDER BY omzet DESC
    `;

    const nsUrl = `https://${NS_ACCOUNT}.suitetalk.api.netsuite.com/services/rest/query/v1/suiteql`;
    const response = await fetch(nsUrl, {
      method: 'POST',
      headers: {
        'Content-Type':  'application/json',
        'Prefer':        'transient',
        'Authorization': nsOAuthHeader(nsUrl, 'POST'),
      },
      body: JSON.stringify({ q: query }),
    });

    if (!response.ok) {
      const err = await response.text();
      console.error('NetSuite SuiteQL fout:', err);
      return res.status(502).json({ error: 'NetSuite query mislukt', detail: err });
    }

    const data   = await response.json();
    const totals = (data.items || []).map(row => ({
      channel: row.channel,
      orders:  Number(row.orders),
      omzet:   Number(row.omzet),
    }));

    res.json({ totals, source: 'netsuite', at: new Date().toISOString() });

  } catch (e) {
    console.error('Totals fout:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ─── Health ───────────────────────────────────────────────────────────────────
app.get('/health', (_,res) => res.json({status:'ok',clients:clients.size}));

app.listen(PORT, () => console.log(`🚀 Wovar backend op poort ${PORT}`));
