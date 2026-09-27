import type { ICredentialType, INodeProperties, Icon } from 'n8n-workflow';

/**
 * Holds the shared secret(s) a webhook provider signs requests with.
 *
 * There is no `test` request: a signing secret is only ever used locally to
 * compute an HMAC, so there is no API endpoint that could confirm it. The node
 * provides a local check instead (see `testedBy` in VerifyWebhookSignature).
 */
export class WebhookSigningSecretApi implements ICredentialType {
	name = 'webhookSigningSecretApi';

	displayName = 'Webhook Signing Secret API';

	icon: Icon = {
		light: 'file:../nodes/VerifyWebhookSignature/verifyWebhookSignature.svg',
		dark: 'file:../nodes/VerifyWebhookSignature/verifyWebhookSignature.dark.svg',
	};

	documentationUrl = 'https://github.com/tochinicky/n8n-nodes-webhook-signature#credentials';

	properties: INodeProperties[] = [
		{
			displayName: 'Signing Secret',
			name: 'secret',
			type: 'string',
			typeOptions: { password: true },
			required: true,
			default: '',
			description:
				'The secret the provider signs webhooks with, e.g. a Stripe endpoint secret (whsec_...), a GitHub webhook secret or a Slack signing secret',
		},
		{
			displayName: 'Secondary Signing Secret',
			name: 'secondarySecret',
			type: 'string',
			typeOptions: { password: true },
			default: '',
			description:
				'Optional. While rotating secrets, put the other secret here so requests signed with either one are accepted. Remove it once the rotation is complete.',
		},
	];
}
