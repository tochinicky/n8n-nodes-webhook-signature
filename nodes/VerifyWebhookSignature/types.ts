export type Provider = 'stripe' | 'github' | 'slack' | 'generic';

export type HashAlgorithm = 'sha1' | 'sha256' | 'sha512';

export type SignatureEncoding = 'hex' | 'base64';

export type FailureReason =
	| 'missing_header'
	| 'malformed_header'
	| 'raw_body_missing'
	| 'timestamp_missing'
	| 'timestamp_outside_tolerance'
	| 'signature_mismatch';

/** Request headers as the n8n Webhook node exposes them (Node's IncomingHttpHeaders). */
export type Headers = Record<string, string | string[] | undefined>;

export interface Secrets {
	primary: string;
	/** Optional second secret, accepted alongside the primary during a rotation window. */
	secondary?: string;
}

export interface GenericOptions {
	signatureHeader: string;
	algorithm: HashAlgorithm;
	encoding: SignatureEncoding;
	/** Stripped from the header value before comparing, e.g. `sha256=`. */
	prefix: string;
	/** Empty string means the provider sends no timestamp. */
	timestampHeader: string;
	/** Supports the `{body}` and `{timestamp}` placeholders. */
	payloadTemplate: string;
}

export interface VerifyOptions {
	/** Maximum allowed age of the request timestamp, in seconds. `0` disables the check. */
	toleranceSeconds: number;
	/** Required when the provider is `generic`. */
	generic?: GenericOptions;
}

/**
 * What a provider module extracts from a request: the exact bytes that were
 * signed, the signature(s) the sender claims, and how to compute our own.
 * Providers only parse; all cryptography happens in `verify.ts`.
 */
export interface SignedRequest {
	signedPayload: Buffer;
	/** Signatures as sent (prefix removed). More than one means "any of these may match". */
	candidates: string[];
	algorithm: HashAlgorithm;
	encoding: SignatureEncoding;
	/** Unix seconds, or null when the provider doesn't send a timestamp. */
	timestamp: number | null;
}

/** A provider either understands the request or explains why it can't. */
export type ParseResult =
	| { ok: true; request: SignedRequest }
	| { ok: false; reason: FailureReason; timestamp?: number | null };

export interface VerificationResult {
	valid: boolean;
	provider: Provider;
	reason: FailureReason | null;
	/** Human-readable hint for the reason. Never contains secrets or signatures. */
	message: string | null;
	matchedSecret: 'primary' | 'secondary' | null;
	timestamp: number | null;
	verifiedAt: string;
}
