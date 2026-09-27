import { createHmac, timingSafeEqual } from 'crypto';

import { parseGeneric } from './providers/generic';
import { parseGitHub } from './providers/github';
import { parseSlack } from './providers/slack';
import { parseStripe } from './providers/stripe';
import type {
	FailureReason,
	Headers,
	ParseResult,
	Provider,
	Secrets,
	SignedRequest,
	VerificationResult,
	VerifyOptions,
} from './types';

export const REASON_MESSAGES: Record<FailureReason, string> = {
	missing_header: 'The signature header is missing from the request.',
	malformed_header: 'The signature or timestamp header is not in the format this provider uses.',
	raw_body_missing:
		"No raw request body found. Enable 'Raw Body' in the Webhook node's options so the exact request bytes are available.",
	timestamp_missing: 'The request has no timestamp, so it cannot be checked for replay.',
	timestamp_outside_tolerance:
		'The request timestamp is outside the allowed tolerance. It may be a replayed request, or the server clock may be wrong.',
	signature_mismatch: 'The signature does not match. The request was not signed with this secret.',
};

function parse(
	provider: Provider,
	headers: Headers,
	rawBody: Buffer,
	options: VerifyOptions,
): ParseResult {
	switch (provider) {
		case 'stripe':
			return parseStripe(headers, rawBody);
		case 'github':
			return parseGitHub(headers, rawBody);
		case 'slack':
			return parseSlack(headers, rawBody);
		case 'generic':
			if (!options.generic) throw new Error('Generic HMAC options are required');
			return parseGeneric(headers, rawBody, options.generic);
	}
}

// timingSafeEqual throws on unequal lengths. A signature's length is public, so returning early leaks nothing.
export function constantTimeEqual(a: string, b: string): boolean {
	const bufferA = Buffer.from(a, 'utf8');
	const bufferB = Buffer.from(b, 'utf8');
	if (bufferA.length !== bufferB.length) return false;
	return timingSafeEqual(bufferA, bufferB);
}

function findMatchingSecret(
	request: SignedRequest,
	secrets: Secrets,
): 'primary' | 'secondary' | null {
	const toTry: Array<['primary' | 'secondary', string]> = [['primary', secrets.primary]];
	if (secrets.secondary) toTry.push(['secondary', secrets.secondary]);

	// Hex is case-insensitive; Base64 is not.
	const candidates =
		request.encoding === 'hex'
			? request.candidates.map((c) => c.trim().toLowerCase())
			: request.candidates.map((c) => c.trim());

	for (const [label, secret] of toTry) {
		const expected = createHmac(request.algorithm, secret)
			.update(request.signedPayload)
			.digest(request.encoding);
		if (candidates.some((candidate) => constantTimeEqual(candidate, expected))) return label;
	}
	return null;
}

function result(
	provider: Provider,
	now: Date,
	fields: Partial<Pick<VerificationResult, 'reason' | 'matchedSecret' | 'timestamp'>>,
): VerificationResult {
	const reason = fields.reason ?? null;
	return {
		valid: reason === null,
		provider,
		reason,
		message: reason === null ? null : REASON_MESSAGES[reason],
		matchedSecret: fields.matchedSecret ?? null,
		timestamp: fields.timestamp ?? null,
		verifiedAt: now.toISOString(),
	};
}

// Signature is checked before the timestamp (Stripe's documented order), so
// timestamp_outside_tolerance only ever describes a genuinely signed request.
export function verify(
	provider: Provider,
	rawBody: Buffer | null,
	headers: Headers,
	secrets: Secrets,
	options: VerifyOptions,
	now: Date,
): VerificationResult {
	if (rawBody === null) return result(provider, now, { reason: 'raw_body_missing' });

	const parsed = parse(provider, headers, rawBody, options);
	if (!parsed.ok) {
		return result(provider, now, { reason: parsed.reason, timestamp: parsed.timestamp });
	}
	const { request } = parsed;

	const matchedSecret = findMatchingSecret(request, secrets);
	if (matchedSecret === null) {
		return result(provider, now, { reason: 'signature_mismatch', timestamp: request.timestamp });
	}

	if (request.timestamp !== null && options.toleranceSeconds > 0) {
		const ageSeconds = Math.abs(Math.floor(now.getTime() / 1000) - request.timestamp);
		if (ageSeconds > options.toleranceSeconds) {
			return result(provider, now, {
				reason: 'timestamp_outside_tolerance',
				timestamp: request.timestamp,
			});
		}
	}

	return result(provider, now, { matchedSecret, timestamp: request.timestamp });
}
