import { getHeader, parseTimestamp } from '../headers';
import type { Headers, ParseResult } from '../types';

const PREFIX = 'v0=';

// https://docs.slack.dev/authentication/verifying-requests-from-slack
export function parseSlack(headers: Headers, rawBody: Buffer): ParseResult {
	const signature = getHeader(headers, 'x-slack-signature');
	if (signature.status === 'missing') return { ok: false, reason: 'missing_header' };
	if (signature.status === 'malformed' || !signature.value.startsWith(PREFIX)) {
		return { ok: false, reason: 'malformed_header' };
	}

	const timestampHeader = getHeader(headers, 'x-slack-request-timestamp');
	if (timestampHeader.status === 'missing') return { ok: false, reason: 'timestamp_missing' };
	if (timestampHeader.status === 'malformed') return { ok: false, reason: 'malformed_header' };
	const timestamp = parseTimestamp(timestampHeader.value);
	if (timestamp === null) return { ok: false, reason: 'malformed_header' };

	return {
		ok: true,
		request: {
			// Use the header text, not the parsed number, so the bytes match what Slack signed.
			signedPayload: Buffer.concat([Buffer.from(`v0:${timestampHeader.value.trim()}:`), rawBody]),
			candidates: [signature.value.slice(PREFIX.length)],
			algorithm: 'sha256',
			encoding: 'hex',
			timestamp,
		},
	};
}
