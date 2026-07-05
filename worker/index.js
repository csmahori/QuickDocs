/**
 * EasyDocuments — Razorpay Payment Worker
 * Cloudflare Worker: handles order creation + signature verification
 *
 * Required secrets (set via: wrangler secret put <NAME>):
 *   RAZORPAY_KEY_ID
 *   RAZORPAY_KEY_SECRET
 *
 * Deployed via GitHub Actions (CLOUDFLARE_API_TOKEN secret, renewed 2026-07-04).
 */

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

/**
 * ── COUPONS — EDIT THIS TABLE ────────────────────────────────────
 * 'CODE': { pct: percent-off (1–100), active: true|false }
 * Set active:false to disable a code without deleting it.
 * Changes require redeploy: cd worker && npx wrangler deploy
 */
const COUPONS = {
  'SAVE50':  { pct: 50,  active: true },
  'HARDA75': { pct: 75,  active: true },
  'FREE100': { pct: 100, active: true },
};

function lookupCoupon(raw) {
  const code = String(raw || '').trim().toUpperCase();
  const c = COUPONS[code];
  return (c && c.active) ? { code, pct: c.pct } : null;
}

/* Discount in whole rupees (matches frontend display), floor ₹1 (Razorpay min) */
function discountedPaise(basePaise, pct) {
  const rupees = Math.max(1, Math.round((basePaise / 100) * (100 - pct) / 100));
  return rupees * 100;
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS, 'Content-Type': 'application/json' },
  });
}

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: CORS });
    }

    if (request.method !== 'POST') {
      return new Response('Method not allowed', { status: 405 });
    }

    const url = new URL(request.url);

    try {
      // ── VALIDATE COUPON ──────────────────────────────────────────
      if (url.pathname === '/validate-coupon') {
        const body = await request.json();
        const c = lookupCoupon(body.code);
        return c ? json({ valid: true, code: c.code, pct: c.pct })
                 : json({ valid: false });
      }

      // ── CREATE ORDER ─────────────────────────────────────────────
      if (url.pathname === '/create-order') {
        const body = await request.json();
        let amount = Number(body.amount) || 900; // paise (₹9 default)

        // Apply coupon server-side (authoritative — client discount is display-only)
        if (body.coupon) {
          const c = lookupCoupon(body.coupon);
          if (!c) return json({ error: 'Invalid or inactive coupon' }, 400);
          if (c.pct >= 100) return json({ error: 'Free coupon — no payment required' }, 400);
          amount = discountedPaise(amount, c.pct);
        }

        const rzpResp = await fetch('https://api.razorpay.com/v1/orders', {
          method: 'POST',
          headers: {
            'Authorization': 'Basic ' + btoa(`${env.RAZORPAY_KEY_ID.trim()}:${env.RAZORPAY_KEY_SECRET.trim()}`),
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            amount,
            currency: 'INR',
            receipt: `hmw_${Date.now()}`,
          }),
        });

        const order = await rzpResp.json();
        if (!rzpResp.ok) {
          return json({ error: order.error?.description || 'Order creation failed' }, 400);
        }

        return json({ order_id: order.id, amount: order.amount, currency: order.currency });
      }

      // ── VERIFY PAYMENT ───────────────────────────────────────────
      if (url.pathname === '/verify-payment') {
        const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = await request.json();

        if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
          return json({ error: 'Missing payment fields' }, 400);
        }

        const message = `${razorpay_order_id}|${razorpay_payment_id}`;

        const key = await crypto.subtle.importKey(
          'raw',
          new TextEncoder().encode(env.RAZORPAY_KEY_SECRET.trim()),
          { name: 'HMAC', hash: 'SHA-256' },
          false,
          ['sign']
        );

        const sigBuffer = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message));
        const expected = Array.from(new Uint8Array(sigBuffer))
          .map(b => b.toString(16).padStart(2, '0'))
          .join('');

        if (expected === razorpay_signature) {
          return json({ verified: true, payment_id: razorpay_payment_id });
        }

        return json({ verified: false, error: 'Signature mismatch' }, 400);
      }

      return new Response('Not found', { status: 404 });

    } catch (err) {
      return json({ error: err.message }, 500);
    }
  },
};
