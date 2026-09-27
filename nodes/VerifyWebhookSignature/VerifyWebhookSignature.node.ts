import type {
	ICredentialTestFunctions,
	ICredentialsDecrypted,
	IDataObject,
	IExecuteFunctions,
	INodeCredentialTestResult,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
} from 'n8n-workflow';
import { NodeConnectionTypes, NodeOperationError } from 'n8n-workflow';

import type {
	GenericOptions,
	HashAlgorithm,
	Headers,
	Provider,
	SignatureEncoding,
	VerifyOptions,
} from './types';
import { verify } from './verify';

/** Reads a dot-separated path such as `headers` or `request.headers` from item JSON. */
function getPath(json: IDataObject, path: string): unknown {
	let current: unknown = json;
	for (const key of path.split('.').filter((k) => k !== '')) {
		if (current === null || typeof current !== 'object') return undefined;
		current = (current as IDataObject)[key];
	}
	return current;
}

// usableAsTool is deliberately not set: this node needs the raw request body as
// binary data, which an AI agent's tool call cannot provide.
// eslint-disable-next-line @n8n/community-nodes/node-usable-as-tool
export class VerifyWebhookSignature implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'Verify Webhook Signature',
		name: 'verifyWebhookSignature',
		icon: {
			light: 'file:verifyWebhookSignature.svg',
			dark: 'file:verifyWebhookSignature.dark.svg',
		},
		group: ['transform'],
		version: [1],
		subtitle: '={{$parameter["provider"]}}',
		description:
			'Verify the HMAC signature of a webhook from Stripe, GitHub, Slack or any HMAC-signing provider',
		defaults: {
			name: 'Verify Webhook Signature',
		},
		inputs: [NodeConnectionTypes.Main],
		outputs: [NodeConnectionTypes.Main, NodeConnectionTypes.Main],
		outputNames: ['Valid', 'Invalid'],
		credentials: [
			{
				name: 'webhookSigningSecretApi',
				required: true,
				testedBy: 'webhookSigningSecretTest',
			},
		],
		properties: [
			{
				displayName:
					"Turn on 'Raw Body' in the Webhook node's options. Signatures are computed over the exact bytes received, and the parsed JSON body cannot be used to recreate them.",
				name: 'rawBodyNotice',
				type: 'notice',
				default: '',
			},
			{
				displayName: 'Provider',
				name: 'provider',
				type: 'options',
				noDataExpression: true,
				options: [
					{
						name: 'Generic HMAC',
						value: 'generic',
						description: 'Configure the header, algorithm, encoding and signed payload yourself',
					},
					{
						name: 'GitHub',
						value: 'github',
						description: 'X-Hub-Signature-256 header',
					},
					{
						name: 'Slack',
						value: 'slack',
						description: 'X-Slack-Signature and X-Slack-Request-Timestamp headers',
					},
					{
						name: 'Stripe',
						value: 'stripe',
						description: 'Stripe-Signature header',
					},
				],
				default: 'stripe',
			},
			{
				displayName: 'Signature Header',
				name: 'signatureHeader',
				type: 'string',
				required: true,
				default: 'x-signature',
				placeholder: 'x-shopify-hmac-sha256',
				description: 'Name of the header that carries the signature. Case-insensitive.',
				displayOptions: { show: { provider: ['generic'] } },
			},
			{
				displayName: 'Algorithm',
				name: 'algorithm',
				type: 'options',
				options: [
					{ name: 'SHA-1', value: 'sha1' },
					{ name: 'SHA-256', value: 'sha256' },
					{ name: 'SHA-512', value: 'sha512' },
				],
				default: 'sha256',
				description: 'Hash function used for the HMAC',
				displayOptions: { show: { provider: ['generic'] } },
			},
			{
				displayName: 'Signature Encoding',
				name: 'encoding',
				type: 'options',
				options: [
					{ name: 'Hex', value: 'hex' },
					{ name: 'Base64', value: 'base64' },
				],
				default: 'hex',
				description: 'How the provider encodes the signature in the header',
				displayOptions: { show: { provider: ['generic'] } },
			},
			{
				displayName: 'Signature Prefix',
				name: 'prefix',
				type: 'string',
				default: '',
				placeholder: 'sha256=',
				description:
					'Text before the signature in the header value, removed before comparing. Leave empty if there is none.',
				displayOptions: { show: { provider: ['generic'] } },
			},
			{
				displayName: 'Timestamp Header',
				name: 'timestampHeader',
				type: 'string',
				default: '',
				placeholder: 'x-webhook-timestamp',
				description:
					'Header carrying the request time in Unix seconds. Setting it turns on the replay check. Leave empty if the provider sends no timestamp.',
				displayOptions: { show: { provider: ['generic'] } },
			},
			{
				displayName: 'Signed Payload Template',
				name: 'payloadTemplate',
				type: 'string',
				default: '{body}',
				placeholder: '{timestamp}.{body}',
				description:
					'What the provider signs. Use {body} for the raw request body and {timestamp} for the timestamp header value.',
				displayOptions: { show: { provider: ['generic'] } },
			},
			{
				displayName: 'Timestamp Tolerance (Seconds)',
				name: 'toleranceSeconds',
				type: 'number',
				typeOptions: { minValue: 0 },
				default: 300,
				description:
					'Reject requests whose timestamp is further than this from the current time, to block replays. 0 turns the check off (not recommended). GitHub sends no timestamp, so this has no effect for it.',
				displayOptions: { show: { provider: ['stripe', 'slack', 'generic'] } },
			},
			{
				displayName: 'On Invalid Signature',
				name: 'onInvalid',
				type: 'options',
				options: [
					{
						name: 'Route to Invalid Output',
						value: 'route',
						description: 'Send the item to the Invalid output so the workflow can respond, e.g. with a 401',
					},
					{
						name: 'Stop Workflow With Error',
						value: 'error',
						description: 'Fail the execution',
					},
				],
				default: 'route',
			},
			{
				displayName: 'Options',
				name: 'options',
				type: 'collection',
				placeholder: 'Add Option',
				default: {},
				options: [
					{
						displayName: 'Raw Body Binary Property',
						name: 'rawBodyProperty',
						type: 'string',
						default: 'data',
						description:
							"Binary property holding the raw request body. The Webhook node uses 'data' when Raw Body is on.",
					},
					{
						displayName: 'Headers Field',
						name: 'headersField',
						type: 'string',
						default: 'headers',
						description:
							"Path in the item's JSON to the request headers. The Webhook node uses 'headers'.",
					},
				],
			},
		],
	};

	methods = {
		credentialTest: {
			/**
			 * A signing secret has no API to test against, so this checks what can be
			 * checked locally: that a secret is set and has no stray whitespace from
			 * copy-pasting, which would make every signature fail to match.
			 */
			async webhookSigningSecretTest(
				this: ICredentialTestFunctions,
				credential: ICredentialsDecrypted,
			): Promise<INodeCredentialTestResult> {
				const data = credential.data ?? {};
				for (const [field, label] of [
					['secret', 'Signing Secret'],
					['secondarySecret', 'Secondary Signing Secret'],
				] as const) {
					const value = String(data[field] ?? '');
					if (field === 'secret' && value === '') {
						return { status: 'Error', message: `${label} is empty` };
					}
					if (value !== value.trim()) {
						return {
							status: 'Error',
							message: `${label} has leading or trailing whitespace. Remove it, or signatures will never match.`,
						};
					}
				}
				return {
					status: 'OK',
					message: 'Secret is set. It can only be confirmed by verifying a real webhook.',
				};
			},
		},
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const items = this.getInputData();
		const validItems: INodeExecutionData[] = [];
		const invalidItems: INodeExecutionData[] = [];

		const credentials = await this.getCredentials('webhookSigningSecretApi');
		const secrets = {
			primary: String(credentials.secret ?? ''),
			secondary: String(credentials.secondarySecret ?? '') || undefined,
		};
		if (secrets.primary === '') {
			throw new NodeOperationError(this.getNode(), 'The Webhook Signing Secret credential has no secret set');
		}

		for (let itemIndex = 0; itemIndex < items.length; itemIndex++) {
			const item = items[itemIndex];
			const provider = this.getNodeParameter('provider', itemIndex) as Provider;
			const onInvalid = this.getNodeParameter('onInvalid', itemIndex) as 'route' | 'error';
			const extra = this.getNodeParameter('options', itemIndex, {}) as {
				rawBodyProperty?: string;
				headersField?: string;
			};
			const rawBodyProperty = extra.rawBodyProperty || 'data';
			const headersField = extra.headersField || 'headers';

			const options: VerifyOptions = {
				toleranceSeconds:
					provider === 'github'
						? 0
						: (this.getNodeParameter('toleranceSeconds', itemIndex, 300) as number),
			};
			if (provider === 'generic') {
				const generic: GenericOptions = {
					signatureHeader: this.getNodeParameter('signatureHeader', itemIndex) as string,
					algorithm: this.getNodeParameter('algorithm', itemIndex) as HashAlgorithm,
					encoding: this.getNodeParameter('encoding', itemIndex) as SignatureEncoding,
					prefix: this.getNodeParameter('prefix', itemIndex, '') as string,
					timestampHeader: this.getNodeParameter('timestampHeader', itemIndex, '') as string,
					payloadTemplate: this.getNodeParameter('payloadTemplate', itemIndex, '{body}') as string,
				};
				if (generic.signatureHeader.trim() === '') {
					throw new NodeOperationError(this.getNode(), 'Signature Header must not be empty', {
						itemIndex,
					});
				}
				options.generic = generic;
			}

			const headers = getPath(item.json, headersField);
			const headerMap: Headers =
				headers !== null && typeof headers === 'object' ? (headers as Headers) : {};

			// Never fall back to re-serialising item.json.body: that produces different
			// bytes from the ones the provider signed, so it could only ever fail.
			const rawBody = item.binary?.[rawBodyProperty]
				? await this.helpers.getBinaryDataBuffer(itemIndex, rawBodyProperty)
				: null;

			const verification = verify(provider, rawBody, headerMap, secrets, options, new Date());

			if (!verification.valid && onInvalid === 'error' && !this.continueOnFail()) {
				throw new NodeOperationError(
					this.getNode(),
					`Webhook signature verification failed: ${verification.reason}`,
					{ itemIndex, description: verification.message ?? undefined },
				);
			}

			const output: INodeExecutionData = {
				json: { ...item.json, signatureVerification: { ...verification } },
				pairedItem: { item: itemIndex },
			};
			if (item.binary) output.binary = item.binary;

			(verification.valid ? validItems : invalidItems).push(output);
		}

		return [validItems, invalidItems];
	}
}
