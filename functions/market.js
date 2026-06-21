// functions/market.js  —  Cloudflare Pages Function
// Serves ~15-min delayed quotes + price history for the 5 allowed ETFs.
// Routes:
//   GET /market?symbols=SPY,VOO,QQQ,VGT,SMH   -> { quotes: {SYM:{price,prevClose,changePct,asOf,spark[]}}, asOf }
//   GET /market?symbol=SPY&range=1y           -> { symbol, price, prevClose, changePct, closes[], timestamps[], asOf }

const ALLOWED = ['SPY', 'VOO', 'QQQ', 'VGT', 'SMH'];
const RANGE_INTERVAL = { '1mo': '1d', '3mo': '1d', '6mo': '1d', '1y': '1wk', '5y': '1mo', 'max': '1mo' };

export async function onRequestGet(context) {
  const url = new URL(context.request.url);
  const headers = {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Cache-Control': 'public, max-age=60'
  };
  try {
    // Annual calendar-year total returns for all ETFs (auto-updates as years complete)
    if (url.searchParams.get('annual')) {
      const out = {};
      await Promise.all(ALLOWED.map(async sym => {
        try { out[sym] = await annualReturns(sym); } catch (e) { out[sym] = {}; }
      }));
      return json({ annual: out, lastCompleteYear: new Date().getUTCFullYear() - 1, asOf: Date.now() }, 200,
        { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*', 'Cache-Control': 'public, max-age=21600' });
    }
    const single = url.searchParams.get('symbol');
    if (single) {
      const sym = single.toUpperCase();
      if (!ALLOWED.includes(sym)) return json({ error: 'symbol not allowed' }, 400, headers);
      const range = (url.searchParams.get('range') || '1y').toLowerCase();
      const interval = RANGE_INTERVAL[range] || '1d';
      const d = await fetchChart(sym, range, interval);
      return json(d, 200, headers);
    }
    const symsParam = url.searchParams.get('symbols') || '';
    const requested = symsParam.split(',').map(s => s.trim().toUpperCase()).filter(s => ALLOWED.includes(s));
    const list = requested.length ? requested : ALLOWED;
    const quotes = {};
    let asOf = 0;
    await Promise.all(list.map(async sym => {
      try {
        const d = await fetchChart(sym, '1mo', '1d');
        quotes[sym] = { symbol: sym, price: d.price, prevClose: d.prevClose, changePct: d.changePct, asOf: d.asOf, spark: d.closes.slice(-30) };
        if (d.asOf > asOf) asOf = d.asOf;
      } catch (e) {
        quotes[sym] = { symbol: sym, error: true };
      }
    }));
    return json({ quotes, asOf }, 200, headers);
  } catch (e) {
    return json({ error: String(e && e.message || e) }, 502, headers);
  }
}

export function onRequestOptions() {
  return new Response(null, {
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type'
    }
  });
}

async function fetchChart(sym, range, interval) {
  const u = `https://query1.finance.yahoo.com/v8/finance/chart/${encodeURIComponent(sym)}?range=${range}&interval=${interval}&includePrePost=false`;
  const r = await fetch(u, {
    headers: { 'User-Agent': 'Mozilla/5.0 (compatible; BetterDailyLab/1.0)', 'Accept': 'application/json' },
    cf: { cacheTtl: 60, cacheEverything: true }
  });
  if (!r.ok) throw new Error('upstream ' + r.status);
  const j = await r.json();
  const res = j && j.chart && j.chart.result && j.chart.result[0];
  if (!res) throw new Error('no data');
  const meta = res.meta || {};
  const ts = res.timestamp || [];
  const q = (res.indicators && res.indicators.quote && res.indicators.quote[0]) || {};
  const rawCloses = q.close || [];
  const timestamps = [], closes = [];
  for (let i = 0; i < rawCloses.length; i++) {
    if (rawCloses[i] != null) { timestamps.push(ts[i]); closes.push(round2(rawCloses[i])); }
  }
  const price = meta.regularMarketPrice != null ? round2(meta.regularMarketPrice) : (closes.length ? closes[closes.length - 1] : null);
  let prevClose = meta.chartPreviousClose != null ? meta.chartPreviousClose : (meta.previousClose != null ? meta.previousClose : (closes.length > 1 ? closes[closes.length - 2] : price));
  prevClose = round2(prevClose);
  const changePct = prevClose ? Math.round(((price - prevClose) / prevClose) * 10000) / 100 : 0;
  const asOf = meta.regularMarketTime ? meta.regularMarketTime * 1000 : Date.now();
  return { symbol: sym, price, prevClose, changePct, closes, timestamps, asOf, currency: meta.currency || 'USD' };
}

async function annualReturns(sym) {
  const u = `https://query1.finance.yahoo.com/v8/finance/chart/${encodeURIComponent(sym)}?range=max&interval=1mo`;
  const r = await fetch(u, { headers: { 'User-Agent': 'Mozilla/5.0 (compatible; BetterDailyLab/1.0)', 'Accept': 'application/json' }, cf: { cacheTtl: 21600, cacheEverything: true } });
  if (!r.ok) throw new Error('upstream ' + r.status);
  const j = await r.json();
  const res = j && j.chart && j.chart.result && j.chart.result[0];
  if (!res) throw new Error('no data');
  const ts = res.timestamp || [];
  const adj = (res.indicators && res.indicators.adjclose && res.indicators.adjclose[0] && res.indicators.adjclose[0].adjclose)
    || (res.indicators && res.indicators.quote && res.indicators.quote[0] && res.indicators.quote[0].close) || [];
  const yearEnd = {}; // calendar year -> last available (December) adjusted close
  for (let i = 0; i < adj.length; i++) { if (adj[i] == null) continue; const y = new Date(ts[i] * 1000).getUTCFullYear(); yearEnd[y] = adj[i]; }
  const cur = new Date().getUTCFullYear();
  const out = {};
  Object.keys(yearEnd).map(Number).sort((a, b) => a - b).forEach(y => {
    if (y >= cur) return;                       // only fully complete calendar years
    if (yearEnd[y - 1] != null) out[y] = Math.round((yearEnd[y] / yearEnd[y - 1] - 1) * 10000) / 100;
  });
  return out;
}

function round2(x) { return x == null ? null : Math.round(x * 100) / 100; }
function json(obj, status, headers) { return new Response(JSON.stringify(obj), { status, headers }); }
