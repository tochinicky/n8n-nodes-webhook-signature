import { createHmac } from 'crypto';

export const FAKE_PRIMARY = 'whsec_test_primary_not_real';
export const FAKE_SECONDARY = 'whsec_test_secondary_not_real';

export const NOW = new Date('2026-09-27T10:00:00.000Z');
export const NOW_SECONDS = Math.floor(NOW.getTime() / 1000);

export function hmac(
	secret: string,
	payload: string | Buffer,
	algorithm = 'sha256',
	encoding: 'hex' | 'base64' = 'hex',
): string {
	return createHmac(algorithm, secret).update(payload).digest(encoding);
}

export function stripeHeader(body: string, timestamp: number, ...secrets: string[]): string {
	const signatures = secrets.map((secret) => `v1=${hmac(secret, `${timestamp}.${body}`)}`);
	return [`t=${timestamp}`, ...signatures].join(',');
}

export function slackHeaders(body: string, timestamp: number, secret: string) {
	return {
		'x-slack-signature': `v0=${hmac(secret, `v0:${timestamp}:${body}`)}`,
		'x-slack-request-timestamp': String(timestamp),
	};
}
