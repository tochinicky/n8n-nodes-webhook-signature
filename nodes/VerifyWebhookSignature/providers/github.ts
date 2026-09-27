import { getHeader } from '../headers';
import type { Headers, ParseResult } from '../types';

const PREFIX = 'sha256=';

// The legacy SHA-1 `X-Hub-Signature` header is deliberately not supported.
// https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries
export function parseGitHub(headers: Headers, rawBody: Buffer): ParseResult {
	const header = getHeader(headers, 'x-hub-signature-256');
	if (header.status === 'missing') return { ok: false, reason: 'missing_header' };
	if (header.status === 'malformed' || !header.value.startsWith(PREFIX)) {
		return { ok: false, reason: 'malformed_header' };
	}

	return {
		ok: true,
		request: {
			signedPayload: rawBody,
			candidates: [header.value.slice(PREFIX.length)],
			algorithm: 'sha256',
			encoding: 'hex',
			timestamp: null,
		},
	};
}
