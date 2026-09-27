import { getHeader, parseTimestamp } from '../headers';
import type { Headers, ParseResult } from '../types';

// `Stripe-Signature: t=<unix>,v1=<hex>[,v1=<hex>...]`. Stripe sends one v1 per active
// secret while one is being rolled; v0 is test-mode only and ignored.
// https://docs.stripe.com/webhooks#verify-manually
export function parseStripe(headers: Headers, rawBody: Buffer): ParseResult {
	const header = getHeader(headers, 'stripe-signature');
	if (header.status === 'missing') return { ok: false, reason: 'missing_header' };
	if (header.status === 'malformed') return { ok: false, reason: 'malformed_header' };

	const timestamps: string[] = [];
	const v1Signatures: string[] = [];
	for (const part of header.value.split(',')) {
		const separator = part.indexOf('=');
		if (separator === -1) continue;
		const key = part.slice(0, separator).trim();
		const value = part.slice(separator + 1).trim();
		if (key === 't') timestamps.push(value);
		if (key === 'v1' && value !== '') v1Signatures.push(value);
	}

	if (timestamps.length !== 1 || v1Signatures.length === 0) {
		return { ok: false, reason: 'malformed_header' };
	}
	const timestamp = parseTimestamp(timestamps[0]);
	if (timestamp === null) return { ok: false, reason: 'malformed_header' };

	return {
		ok: true,
		request: {
			signedPayload: Buffer.concat([Buffer.from(`${timestamps[0].trim()}.`), rawBody]),
			candidates: v1Signatures,
			algorithm: 'sha256',
			encoding: 'hex',
			timestamp,
		},
	};
}
