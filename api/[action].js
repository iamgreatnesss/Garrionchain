import { createClient } from '@supabase/supabase-js';
import crypto from 'node:crypto';

const db = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY, { auth: { persistSession: false } });
const OFFICIAL = (process.env.OFFICIAL_CA || '').toLowerCase();
const FAST = process.env.FAST_CHECK === '1';
const TAB_BY_HANDLE = { degenbro__: 'degen', garrionchain: 'ann' };
const PUBLIC = 'id,url,handle,author_name,body,tab,upvotes,approved_at,created_at';
const hash = (ip) => crypto.createHash('sha256').update(ip + (process.env.HASH_SALT || '')).digest('hex');
const clean = (s) => String(s || '').replace(/[,()%]/g, ' ').trim().slice(0, 60);
const fail = (status, message) => Object.assign(new Error(message), { status });
const decode = (s) => s.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'")
  .replace(/&mdash;/g, '\u2014').replace(/&#(\d+);/g, (_, n) => String.fromCodePoint(+n)).replace(/&amp;/g, '&');

const scam = (t) =>
  /(airdrop|giveaway|\bclaim\b|connect (your )?wallet|seed phrase|private key|free (mint|tokens?))/i.test(t) ||
  (t.match(/0x[a-fA-F0-9]{40}/g) || []).some((a) => a.toLowerCase() !== OFFICIAL);

async function check(p) {
  let j;
  try {
    const r = await fetch('https://publish.twitter.com/oembed?omit_script=1&url=' + encodeURIComponent(p.url));
    if (r.status === 404 || r.status === 403) return { status: 'rejected', reason: 'We could not read this post. It may be deleted or private.' };
    if (!r.ok) throw new Error('oembed ' + r.status);
    j = await r.json();
  } catch {
    return { check_after: new Date(Date.now() + 60000).toISOString() };
  }
  const m = (j.html || '').match(/<p[^>]*>([\s\S]*?)<\/p>/);
  const body = decode((m ? m[1] : '').replace(/<br\s*\/?>/g, '\n').replace(/<[^>]+>/g, '')).trim();
  const handle = (j.author_url || '').split('/').pop() || p.handle;
  const base = { handle, author_name: j.author_name, body };
  if (TAB_BY_HANDLE[handle.toLowerCase()] && /garri/i.test(body) && !scam(body)) return { ...base, status: 'approved', approved_at: new Date().toISOString(), tab: TAB_BY_HANDLE[handle.toLowerCase()] };
  if (body.length < 100) return { ...base, status: 'rejected', reason: 'Too short: posts need at least 100 characters.' };
  if (!/\$garri\b/i.test(body) && body.length > 240) return { ...base, status: 'review', reason: 'Long post: the $GARRI mention may be further down. Please check.' };
  if (!/\$garri\b/i.test(body)) return { ...base, status: 'rejected', reason: 'No $GARRI found in this post.' };
  if (scam(body)) return { ...base, status: 'review', reason: 'Flagged for a moderator to check.' };
  return { ...base, status: 'approved', approved_at: new Date().toISOString(), tab: TAB_BY_HANDLE[handle.toLowerCase()] || 'c' };
}

async function processDue() {
  const { data } = await db.from('posts').select('*').eq('status', 'pending').lte('check_after', new Date().toISOString()).limit(5);
  await Promise.all((data || []).map(async (p) => db.from('posts').update(await check(p)).eq('id', p.id)));
}

const H = {
  async posts(req) {
    await processDue();
    const { tab, sort, q, handle, device } = req.query;
    let s = db.from('posts').select(PUBLIC).eq('status', 'approved');
    if (handle) s = s.ilike('handle', clean(handle).replace(/^@/, ''));
    else if (tab) s = s.eq('tab', tab);
    if (q) { const c = clean(q).replace(/^@/, ''); s = s.or(`body.ilike.%${c}%,author_name.ilike.%${c}%,handle.ilike.%${c}%`); }
    s = sort === 'top' ? s.order('upvotes', { ascending: false }) : s.order('approved_at', { ascending: false });
    const { data } = await s.limit(100);
    const ids = (data || []).map((p) => p.id);
    const v = ids.length && device ? (await db.from('votes').select('post_id').eq('device', device).in('post_id', ids)).data || [] : [];
    return { posts: data || [], voted: v.map((x) => x.post_id) };
  },

  async mine(req) {
    await processDue();
    const { data } = await db.from('posts').select('id,url,handle,status,reason,upvotes,check_after,created_at')
      .eq('device', req.query.device || '-').order('created_at', { ascending: false }).limit(50);
    return { posts: data || [] };
  },

  async submit(req) {
    const { url, device } = req.body;
    const m = String(url || '').match(/^https?:\/\/(?:www\.|mobile\.)?(?:x|twitter)\.com\/([A-Za-z0-9_]{1,15})\/status\/(\d{5,25})/i);
    if (!m || !device || String(device).length < 8) throw fail(400, 'That is not an X post link.');
    const ip = hash((req.headers['x-forwarded-for'] || '').split(',')[0].trim() || '0');
    if ((await db.from('bans').select('ip_hash').eq('ip_hash', ip).maybeSingle()).data) throw fail(403, 'You cannot submit posts.');
    const { count } = await db.from('posts').select('id', { count: 'exact', head: true })
      .eq('ip_hash', ip).gte('created_at', new Date(Date.now() - 36e5).toISOString());
    if (count >= 3) throw fail(429, 'Limit reached: 3 submissions per hour. Try again later.');
    const delay = FAST ? 5 : 90 + Math.floor(Math.random() * 31);
    const { error } = await db.from('posts').insert({
      tweet_id: m[2], url: `https://x.com/${m[1]}/status/${m[2]}`, handle: m[1], device, ip_hash: ip,
      check_after: new Date(Date.now() + delay * 1000).toISOString(),
    });
    if (error?.code === '23505') throw fail(409, 'This post was already submitted.');
    if (error) throw error;
    return { ok: true };
  },
  async vote(req) {
    const { id, device } = req.body;
    if (!id || !device) throw fail(400, 'Bad request');
    const { data: ex } = await db.from('votes').select('post_id').eq('post_id', id).eq('device', device).maybeSingle();
    if (ex) await db.from('votes').delete().eq('post_id', id).eq('device', device);
    else await db.from('votes').insert({ post_id: id, device });
    const { count } = await db.from('votes').select('post_id', { count: 'exact', head: true }).eq('post_id', id);
    await db.from('posts').update({ upvotes: count }).eq('id', id);
    return { upvotes: count, voted: !ex };
  },

  async report(req) {
    const { id, device } = req.body;
    if (!id || !device) throw fail(400, 'Bad request');
    await db.from('reports').upsert({ post_id: id, device });
    const { count } = await db.from('reports').select('post_id', { count: 'exact', head: true }).eq('post_id', id);
    const u = { reports: count };
    if (count >= 3) { u.status = 'review'; u.reason = 'Hidden after several reports.'; }
    await db.from('posts').update(u).eq('id', id).eq('status', 'approved');
    return { ok: true };
  },

  async click(req) {
    const id = +req.body.id;
    if (!id) throw fail(400, 'Bad request');
    await db.rpc('bump_click', { pid: id });
    return { ok: true };
  },

  async mod(req) {
    const k = Buffer.from(String(req.headers['x-mod-key'] || '')), pw = Buffer.from(process.env.MOD_PASSWORD || '');
    if (!pw.length || k.length !== pw.length || !crypto.timingSafeEqual(k, pw)) throw fail(401, 'Wrong password');
    const { op, id } = req.body;
    if (id) {
      const { data: p } = await db.from('posts').select('handle,ip_hash').eq('id', id).single();
      const U = {
        approve: { status: 'approved', approved_at: new Date().toISOString(), tab: TAB_BY_HANDLE[(p.handle || '').toLowerCase()] || 'c', reports: 0 },
        reject: { status: 'rejected', reason: 'Not accepted by a moderator.' },
        remove: { status: 'removed' },
        tag: { tab: 'ann' },
        dismiss: { reports: 0 },
      }[op];
      if (op === 'ban') {
        await db.from('bans').upsert({ ip_hash: p.ip_hash });
        await db.from('posts').update({ status: 'removed' }).eq('id', id);
      } else if (U) {
        await db.from('posts').update(U).eq('id', id);
        if (op === 'dismiss' || op === 'approve') await db.from('reports').delete().eq('post_id', id);
      }
    }
    const F = 'id,url,handle,author_name,body,tab,status,reports,clicks,upvotes,reason';
    const all = (await db.from('posts').select(F).order('created_at', { ascending: false }).limit(200)).data || [];
    return {
      review: all.filter((x) => x.status === 'review'),
      rejected: all.filter((x) => x.status === 'rejected' && x.body),
      reported: all.filter((x) => x.status === 'approved' && x.reports > 0),
      posts: all.filter((x) => x.status === 'approved'),
      stats: { pending: all.filter((x) => x.status === 'pending').length, clicks: all.reduce((s, x) => s + x.clicks, 0) },
    };
  },
};

export default async function handler(req, res) {
  try {
    const fn = H[req.query.action];
    if (!fn) return res.status(404).json({ error: 'Not found' });
    if (typeof req.body === 'string') { try { req.body = JSON.parse(req.body); } catch { req.body = {}; } }
    req.body = req.body || {};
    res.setHeader('Cache-Control', 'no-store');
    res.json(await fn(req));
  } catch (e) {
    if (!e.status) console.error(e);
    res.status(e.status || 500).json({ error: e.status ? e.message : 'Server error' });
  }
}
