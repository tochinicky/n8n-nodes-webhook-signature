import { getHeader, parseTimestamp } from '../headers';
import type { GenericOptions, Headers, ParseResult } from '../types';

/**
 * Generic HMAC: everything comes from the node's parameters.
 *
 * The template is expanded around the raw body bytes rather than by string
 * replacement on a decoded body, so a non-UTF-8 body is signed exactly as it
 * arrived. `{timestamp}` is substituted first; `{body}` may appear any number
 * of times (normally once).
 */
export function parseGeneric(
	headers: Headers,
	rawBody: Buffer,
	options: GenericOptions,
): ParseResult {
	const header = getHeader(headers, options.signatureHeader);
	if (header.status === 'missing') return { ok: false, reason: 'missing_header' };
	if (header.status === 'malformed') return { ok: false, reason: 'malformed_header' };

	let signature = header.value.trim();
	if (options.prefix !== '') {
		if (!signature.startsWith(options.prefix)) return { ok: false, reason: 'malformed_header' };
		signature = signature.slice(options.prefix.length);
	}

	let timestamp: number | null = null;
	let timestampText = '';
	const usesTimestamp =
		options.timestampHeader.trim() !== '' || options.payloadTemplate.includes('{timestamp}');
	if (usesTimestamp) {
		if (options.timestampHeader.trim() === '') return { ok: false, reason: 'timestamp_missing' };
		const timestampHeader = getHeader(headers, options.timestampHeader);
		if (timestampHeader.status === 'missing') return { ok: false, reason: 'timestamp_missing' };
		if (timestampHeader.status === 'malformed') return { ok: false, reason: 'malformed_header' };
		timestamp = parseTimestamp(timestampHeader.value);
		if (timestamp === null) return { ok: false, reason: 'malformed_header' };
		timestampText = timestampHeader.value.trim();
	}

	const pieces = options.payloadTemplate.split('{timestamp}').join(timestampText).split('{body}');
	const parts: Buffer[] = [];
	pieces.forEach((piece, index) => {
		if (index > 0) parts.push(rawBody);
		parts.push(Buffer.from(piece));
	});

	return {
		ok: true,
		request: {
			signedPayload: Buffer.concat(parts),
			candidates: [signature],
			algorithm: options.algorithm,
			encoding: options.encoding,
			timestamp,
		},
	};
}
