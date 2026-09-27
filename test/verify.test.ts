import { describe, expect, it } from 'vitest';

import type { GenericOptions } from '../nodes/VerifyWebhookSignature/types';
import { constantTimeEqual, verify } from '../nodes/VerifyWebhookSignature/verify';
import {
	FAKE_PRIMARY,
	FAKE_SECONDARY,
	NOW,
	NOW_SECONDS,
	hmac,
	slackHeaders,
	stripeHeader,
} from './helpers';

const TOLERANCE = { toleranceSeconds: 300 };
const body = '{"id":"evt_test","type":"payment_intent.succeeded"}';
const raw = Buffer.from(body);

describe('GitHub', () => {
	// Test vector published in GitHub's docs:
	// https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries#testing-the-webhook-payload-validation
	const docsSecret = "It's a Secret to Everybody";
	const docsPayload = Buffer.from('Hello, World!');
	const docsHeader = {
		'x-hub-signature-256': 'sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17',
	};

	it('accepts the official test vector', () => {
		const result = verify('github', docsPayload, docsHeader, { primary: docsSecret }, TOLERANCE, NOW);
		expect(result).toMatchObject({ valid: true, reason: null, matchedSecret: 'primary', timestamp: null });
	});

	it('rejects the wrong secret', () => {
		const result = verify('github', docsPayload, docsHeader, { primary: FAKE_PRIMARY }, TOLERANCE, NOW);
		expect(result).toMatchObject({ valid: false, reason: 'signature_mismatch' });
	});

	it('reports a missing header', () => {
		const result = verify('github', docsPayload, {}, { primary: docsSecret }, TOLERANCE, NOW);
		expect(result.reason).toBe('missing_header');
	});

	it('rejects a header without the sha256= prefix', () => {
		const headers = { 'x-hub-signature-256': docsHeader['x-hub-signature-256'].slice(7) };
		const result = verify('github', docsPayload, headers, { primary: docsSecret }, TOLERANCE, NOW);
		expect(result.reason).toBe('malformed_header');
	});

	it('looks headers up case-insensitively', () => {
		const headers = { 'X-Hub-Signature-256': docsHeader['x-hub-signature-256'] };
		const result = verify('github', docsPayload, headers, { primary: docsSecret }, TOLERANCE, NOW);
		expect(result.valid).toBe(true);
	});
});

describe('Stripe', () => {
	it('accepts a valid signature within tolerance', () => {
		const headers = { 'stripe-signature': stripeHeader(body, NOW_SECONDS - 30, FAKE_PRIMARY) };
		const result = verify('stripe', raw, headers, { primary: FAKE_PRIMARY }, TOLERANCE, NOW);
		expect(result).toMatchObject({
			valid: true,
			provider: 'stripe',
			matchedSecret: 'primary',
			timestamp: NOW_SECONDS - 30,
			verifiedAt: '2026-09-27T10:00:00.000Z',
		});
	});

	it('rejects a validly signed request that is 10 minutes old', () => {
		const tenMinutesAgo = NOW_SECONDS - 600;
		const headers = { 'stripe-signature': stripeHeader(body, tenMinutesAgo, FAKE_PRIMARY) };
		const result = verify('stripe', raw, headers, { primary: FAKE_PRIMARY }, TOLERANCE, NOW);
		expect(result).toMatchObject({ valid: false, reason: 'timestamp_outside_tolerance', timestamp: tenMinutesAgo });
	});

	it('skips the age check when tolerance is 0', () => {
		const headers = { 'stripe-signature': stripeHeader(body, NOW_SECONDS - 86400, FAKE_PRIMARY) };
		const result = verify('stripe', raw, headers, { primary: FAKE_PRIMARY }, { toleranceSeconds: 0 }, NOW);
		expect(result.valid).toBe(true);
	});

	it('accepts when the second of two v1 signatures matches (Stripe-side rotation)', () => {
		const otherSecret = 'whsec_test_rolled_away_not_real';
		const headers = { 'stripe-signature': stripeHeader(body, NOW_SECONDS, otherSecret, FAKE_PRIMARY) };
		const result = verify('stripe', raw, headers, { primary: FAKE_PRIMARY }, TOLERANCE, NOW);
		expect(result).toMatchObject({ valid: true, matchedSecret: 'primary' });
	});

	it('ignores v0 signatures', () => {
		const v0 = hmac(FAKE_PRIMARY, `${NOW_SECONDS}.${body}`);
		const headers = { 'stripe-signature': `t=${NOW_SECONDS},v1=${'0'.repeat(64)},v0=${v0}` };
		const result = verify('stripe', raw, headers, { primary: FAKE_PRIMARY }, TOLERANCE, NOW);
		expect(result.reason).toBe('signature_mismatch');
	});

	it('reports a malformed header when t= is missing', () => {
		const headers = { 'stripe-signature': `v1=${hmac(FAKE_PRIMARY, body)}` };
		const result = verify('stripe', raw, headers, { primary: FAKE_PRIMARY }, TOLERANCE, NOW);
		expect(result.reason).toBe('malformed_header');
	});

	it('reports a malformed header for a non-numeric timestamp', () => {
		const headers = { 'stripe-signature': `t=yesterday,v1=${'a'.repeat(64)}` };
		const result = verify('stripe', raw, headers, { primary: FAKE_PRIMARY }, TOLERANCE, NOW);
		expect(result.reason).toBe('malformed_header');
	});

	it('rejects a signature from a different timestamp (t cannot be swapped)', () => {
		const signed = stripeHeader(body, NOW_SECONDS - 600, FAKE_PRIMARY);
		const headers = { 'stripe-signature': signed.replace(`t=${NOW_SECONDS - 600}`, `t=${NOW_SECONDS}`) };
		const result = verify('stripe', raw, headers, { primary: FAKE_PRIMARY }, TOLERANCE, NOW);
		expect(result.reason).toBe('signature_mismatch');
	});
});

describe('Slack', () => {
	const formBody = 'token=test&team_id=T0TEST&command=%2Fhello&text=hi';

	it('accepts a valid request', () => {
		const headers = slackHeaders(formBody, NOW_SECONDS, FAKE_PRIMARY);
		const result = verify('slack', Buffer.from(formBody), headers, { primary: FAKE_PRIMARY }, TOLERANCE, NOW);
		expect(result).toMatchObject({ valid: true, provider: 'slack', timestamp: NOW_SECONDS });
	});

	it('rejects a body changed by one byte', () => {
		const headers = slackHeaders(formBody, NOW_SECONDS, FAKE_PRIMARY);
		const tampered = Buffer.from(formBody.replace('text=hi', 'text=ho'));
		const result = verify('slack', tampered, headers, { primary: FAKE_PRIMARY }, TOLERANCE, NOW);
		expect(result.reason).toBe('signature_mismatch');
	});

	it('reports a missing timestamp header', () => {
		const headers = { 'x-slack-signature': slackHeaders(formBody, NOW_SECONDS, FAKE_PRIMARY)['x-slack-signature'] };
		const result = verify('slack', Buffer.from(formBody), headers, { primary: FAKE_PRIMARY }, TOLERANCE, NOW);
		expect(result.reason).toBe('timestamp_missing');
	});

	it('rejects an old request', () => {
		const headers = slackHeaders(formBody, NOW_SECONDS - 301, FAKE_PRIMARY);
		const result = verify('slack', Buffer.from(formBody), headers, { primary: FAKE_PRIMARY }, TOLERANCE, NOW);
		expect(result.reason).toBe('timestamp_outside_tolerance');
	});
});

describe('Generic HMAC', () => {
	const base: GenericOptions = {
		signatureHeader: 'X-Webhook-Signature',
		algorithm: 'sha256',
		encoding: 'hex',
		prefix: '',
		timestampHeader: '',
		payloadTemplate: '{body}',
	};

	it('accepts base64 + prefix + {timestamp}.{body} template', () => {
		const generic: GenericOptions = {
			...base,
			encoding: 'base64',
			prefix: 'sha256=',
			timestampHeader: 'X-Webhook-Timestamp',
			payloadTemplate: '{timestamp}.{body}',
		};
		const signature = hmac(FAKE_PRIMARY, `${NOW_SECONDS}.${body}`, 'sha256', 'base64');
		const headers = {
			'x-webhook-signature': `sha256=${signature}`,
			'x-webhook-timestamp': String(NOW_SECONDS),
		};
		const result = verify('generic', raw, headers, { primary: FAKE_PRIMARY }, { toleranceSeconds: 300, generic }, NOW);
		expect(result).toMatchObject({ valid: true, provider: 'generic', timestamp: NOW_SECONDS });
	});

	it('works as a Shopify preset (base64, body only)', () => {
		const generic: GenericOptions = { ...base, signatureHeader: 'x-shopify-hmac-sha256', encoding: 'base64' };
		const headers = { 'x-shopify-hmac-sha256': hmac(FAKE_PRIMARY, body, 'sha256', 'base64') };
		const result = verify('generic', raw, headers, { primary: FAKE_PRIMARY }, { toleranceSeconds: 300, generic }, NOW);
		expect(result.valid).toBe(true);
	});

	it.each(['sha1', 'sha512'] as const)('supports %s', (algorithm) => {
		const generic: GenericOptions = { ...base, algorithm };
		const headers = { 'x-webhook-signature': hmac(FAKE_PRIMARY, body, algorithm) };
		const result = verify('generic', raw, headers, { primary: FAKE_PRIMARY }, { toleranceSeconds: 300, generic }, NOW);
		expect(result.valid).toBe(true);
	});

	it('reports timestamp_missing when the template needs a timestamp but none is configured', () => {
		const generic: GenericOptions = { ...base, payloadTemplate: '{timestamp}.{body}' };
		const headers = { 'x-webhook-signature': 'irrelevant' };
		const result = verify('generic', raw, headers, { primary: FAKE_PRIMARY }, { toleranceSeconds: 300, generic }, NOW);
		expect(result.reason).toBe('timestamp_missing');
	});

	it('signs the exact body bytes, including non-UTF-8 bytes', () => {
		const binaryBody = Buffer.from([0xff, 0xfe, 0x00, 0x41]);
		const generic: GenericOptions = { ...base, payloadTemplate: 'v1:{body}' };
		const headers = { 'x-webhook-signature': hmac(FAKE_PRIMARY, Buffer.concat([Buffer.from('v1:'), binaryBody])) };
		const result = verify('generic', binaryBody, headers, { primary: FAKE_PRIMARY }, { toleranceSeconds: 300, generic }, NOW);
		expect(result.valid).toBe(true);
	});
});

describe('secret rotation', () => {
	it('reports when the secondary secret matched', () => {
		const headers = { 'stripe-signature': stripeHeader(body, NOW_SECONDS, FAKE_SECONDARY) };
		const secrets = { primary: FAKE_PRIMARY, secondary: FAKE_SECONDARY };
		const result = verify('stripe', raw, headers, secrets, TOLERANCE, NOW);
		expect(result).toMatchObject({ valid: true, matchedSecret: 'secondary' });
	});

	it('does not accept the secondary secret when none is configured', () => {
		const headers = { 'stripe-signature': stripeHeader(body, NOW_SECONDS, FAKE_SECONDARY) };
		const result = verify('stripe', raw, headers, { primary: FAKE_PRIMARY }, TOLERANCE, NOW);
		expect(result.reason).toBe('signature_mismatch');
	});
});

describe('safety', () => {
	it('treats a signature of a different length as a mismatch without throwing', () => {
		const headers = { 'x-hub-signature-256': 'sha256=abc123' };
		expect(() => verify('github', raw, headers, { primary: FAKE_PRIMARY }, TOLERANCE, NOW)).not.toThrow();
		expect(verify('github', raw, headers, { primary: FAKE_PRIMARY }, TOLERANCE, NOW).reason).toBe('signature_mismatch');
	});

	it('constantTimeEqual handles unequal lengths', () => {
		expect(constantTimeEqual('abc', 'abcd')).toBe(false);
		expect(constantTimeEqual('abcd', 'abcd')).toBe(true);
	});

	it('does not accept extra characters after a valid signature', () => {
		const valid = hmac(FAKE_PRIMARY, body);
		const headers = { 'x-hub-signature-256': `sha256=${valid}zz` };
		const result = verify('github', raw, headers, { primary: FAKE_PRIMARY }, TOLERANCE, NOW);
		expect(result.reason).toBe('signature_mismatch');
	});

	it('refuses a header that was sent twice', () => {
		const headers = { 'x-hub-signature-256': [`sha256=${hmac(FAKE_PRIMARY, body)}`, 'sha256=00'] };
		const result = verify('github', raw, headers, { primary: FAKE_PRIMARY }, TOLERANCE, NOW);
		expect(result.reason).toBe('malformed_header');
	});

	it('reports raw_body_missing instead of guessing', () => {
		const result = verify('github', null, {}, { primary: FAKE_PRIMARY }, TOLERANCE, NOW);
		expect(result).toMatchObject({ valid: false, reason: 'raw_body_missing' });
		expect(result.message).toContain("Enable 'Raw Body'");
	});

	it('never includes secrets or signatures in the result', () => {
		const expectedSignature = hmac(FAKE_PRIMARY, `${NOW_SECONDS}.${body}`);
		const secrets = { primary: FAKE_PRIMARY, secondary: FAKE_SECONDARY };
		const cases = [
			verify('stripe', raw, { 'stripe-signature': stripeHeader(body, NOW_SECONDS, FAKE_PRIMARY) }, secrets, TOLERANCE, NOW),
			verify('stripe', raw, { 'stripe-signature': `t=${NOW_SECONDS},v1=${'f'.repeat(64)}` }, secrets, TOLERANCE, NOW),
		];
		for (const result of cases) {
			const serialised = JSON.stringify(result);
			expect(serialised).not.toContain(FAKE_PRIMARY);
			expect(serialised).not.toContain(FAKE_SECONDARY);
			expect(serialised).not.toContain(expectedSignature);
		}
	});
});
