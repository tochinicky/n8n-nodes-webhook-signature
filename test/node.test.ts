import type { IExecuteFunctions, INodeExecutionData } from 'n8n-workflow';
import { describe, expect, it } from 'vitest';

import { VerifyWebhookSignature } from '../nodes/VerifyWebhookSignature/VerifyWebhookSignature.node';
import { FAKE_PRIMARY, hmac } from './helpers';

const body = '{"action":"opened"}';

function webhookItem(headers: Record<string, string>, withRawBody = true): INodeExecutionData {
	return {
		json: { headers, params: {}, query: {}, body: JSON.parse(body) },
		binary: withRawBody
			? { data: { data: Buffer.from(body).toString('base64'), mimeType: 'application/json' } }
			: undefined,
	};
}

function fakeContext(
	items: INodeExecutionData[],
	parameters: Record<string, unknown>,
	continueOnFail = false,
): IExecuteFunctions {
	return {
		getInputData: () => items,
		getCredentials: async () => ({ secret: FAKE_PRIMARY, secondarySecret: '' }),
		getNodeParameter: (name: string, _itemIndex: number, fallback?: unknown) =>
			name in parameters ? parameters[name] : fallback,
		getNode: () => ({ name: 'Verify Webhook Signature', type: 'verifyWebhookSignature' }),
		continueOnFail: () => continueOnFail,
		helpers: {
			getBinaryDataBuffer: async (itemIndex: number, property: string) =>
				Buffer.from(items[itemIndex].binary![property].data, 'base64'),
		},
	} as unknown as IExecuteFunctions;
}

const github = { provider: 'github', onInvalid: 'route', options: {} };
const signedHeaders = { 'x-hub-signature-256': `sha256=${hmac(FAKE_PRIMARY, body)}` };
const forgedHeaders = { 'x-hub-signature-256': `sha256=${hmac('wrong_secret_for_test', body)}` };

describe('VerifyWebhookSignature node', () => {
	const node = new VerifyWebhookSignature();

	it('routes valid items to output 0 and invalid items to output 1', async () => {
		const items = [webhookItem(signedHeaders), webhookItem(forgedHeaders)];
		const [valid, invalid] = await node.execute.call(fakeContext(items, github));

		expect(valid).toHaveLength(1);
		expect(invalid).toHaveLength(1);
		expect(valid[0].json.signatureVerification).toMatchObject({ valid: true, provider: 'github' });
		expect(invalid[0].json.signatureVerification).toMatchObject({ reason: 'signature_mismatch' });
		expect(valid[0].pairedItem).toEqual({ item: 0 });
		expect(invalid[0].pairedItem).toEqual({ item: 1 });
	});

	it('passes the original JSON and binary through', async () => {
		const item = webhookItem(signedHeaders);
		const [[out]] = await node.execute.call(fakeContext([item], github));
		expect(out.json.body).toEqual({ action: 'opened' });
		expect(out.json.headers).toEqual(signedHeaders);
		expect(out.binary).toBe(item.binary);
		expect(item.json.signatureVerification).toBeUndefined();
	});

	it('marks the item invalid when Raw Body was not enabled', async () => {
		const [valid, invalid] = await node.execute.call(
			fakeContext([webhookItem(signedHeaders, false)], github),
		);
		expect(valid).toHaveLength(0);
		expect(invalid[0].json.signatureVerification).toMatchObject({ reason: 'raw_body_missing' });
	});

	it('stops the workflow when On Invalid Signature is set to error', async () => {
		const context = fakeContext([webhookItem(forgedHeaders)], { ...github, onInvalid: 'error' });
		await expect(node.execute.call(context)).rejects.toThrow('signature_mismatch');
	});

	it('routes to Invalid instead of throwing when Continue On Fail is on', async () => {
		const context = fakeContext(
			[webhookItem(forgedHeaders)],
			{ ...github, onInvalid: 'error' },
			true,
		);
		const [valid, invalid] = await node.execute.call(context);
		expect(valid).toHaveLength(0);
		expect(invalid).toHaveLength(1);
	});

	it('reads headers and raw body from custom locations', async () => {
		const item: INodeExecutionData = {
			json: { request: { headers: signedHeaders } },
			binary: {
				rawBody: { data: Buffer.from(body).toString('base64'), mimeType: 'application/json' },
			},
		};
		const parameters = {
			...github,
			options: { headersField: 'request.headers', rawBodyProperty: 'rawBody' },
		};
		const [valid] = await node.execute.call(fakeContext([item], parameters));
		expect(valid).toHaveLength(1);
	});

	it('never puts the secret in the output', async () => {
		const [valid, invalid] = await node.execute.call(
			fakeContext([webhookItem(signedHeaders), webhookItem(forgedHeaders)], github),
		);
		expect(JSON.stringify([valid, invalid])).not.toContain(FAKE_PRIMARY);
	});
});
