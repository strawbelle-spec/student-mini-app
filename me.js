import { createHmac, timingSafeEqual } from 'node:crypto';

function verifyTelegramInitData(initData, botToken) {
  if (!initData || typeof initData !== 'string' || !botToken) return null;

  const params = new URLSearchParams(initData);
  const receivedHash = params.get('hash');
  if (!receivedHash || !/^[a-f0-9]{64}$/i.test(receivedHash)) return null;

  params.delete('hash');
  params.delete('signature');
  const dataCheckString = [...params.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => `${key}=${value}`)
    .join('\n');

  const secretKey = createHmac('sha256', 'WebAppData').update(botToken).digest();
  const calculatedHash = createHmac('sha256', secretKey).update(dataCheckString).digest();
  const suppliedHash = Buffer.from(receivedHash, 'hex');
  if (suppliedHash.length !== calculatedHash.length || !timingSafeEqual(suppliedHash, calculatedHash)) {
    return null;
  }

  const authDate = Number(params.get('auth_date'));
  const now = Math.floor(Date.now() / 1000);
  // Reject missing, future-dated, or older-than-24-hour initData.
  if (!Number.isFinite(authDate) || authDate > now + 60 || now - authDate > 86400) return null;

  let user;
  try {
    user = JSON.parse(params.get('user') || 'null');
  } catch {
    return null;
  }
  if (!user || !Number.isSafeInteger(Number(user.id))) return null;
  return user;
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Content-Type', 'application/json; charset=utf-8');

  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { TELEGRAM_BOT_TOKEN, SUPABASE_URL, SUPABASE_SECRET_KEY } = process.env;
  if (!TELEGRAM_BOT_TOKEN || !SUPABASE_URL || !SUPABASE_SECRET_KEY) {
    return res.status(500).json({ error: 'Server configuration is incomplete' });
  }

  const user = verifyTelegramInitData(req.body?.initData, TELEGRAM_BOT_TOKEN);
  if (!user) return res.status(401).json({ error: 'Telegram authentication failed' });

  const fullName = [user.first_name || '', user.last_name || ''].join(' ').trim() || user.username || 'Student';
  const student = {
    telegram_user_id: String(user.id),
    telegram_username: user.username || null,
    full_name: fullName,
    avatar_url: user.photo_url || null,
  };

  try {
    const baseUrl = SUPABASE_URL.replace(/\/$/, '');
    const response = await fetch(
      `${baseUrl}/rest/v1/students?on_conflict=telegram_user_id&select=id,telegram_user_id,telegram_username,full_name,nim,major,cohort,avatar_url`,
      {
        method: 'POST',
        headers: {
          apikey: SUPABASE_SECRET_KEY,
          Authorization: `Bearer ${SUPABASE_SECRET_KEY}`,
          'Content-Type': 'application/json',
          Prefer: 'resolution=merge-duplicates,return=representation',
        },
        body: JSON.stringify(student),
      },
    );

    if (!response.ok) {
      // Keep upstream details in server logs only; do not expose keys or raw DB errors.
      console.error('Supabase student upsert failed:', response.status, await response.text());
      return res.status(502).json({ error: 'Could not save student profile' });
    }

    const rows = await response.json();
    return res.status(200).json({ student: rows?.[0] || null });
  } catch (error) {
    console.error('Student profile API error:', error);
    return res.status(500).json({ error: 'Unexpected server error' });
  }
}
