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

export type Headers = Record<string, string | string[] | undefined>;

export interface Secrets {
	primary: string;
	secondary?: string;
}

export interface GenericOptions {
	signatureHeader: string;
	algorithm: HashAlgorithm;
	encoding: SignatureEncoding;
	prefix: string;
	timestampHeader: string;
	payloadTemplate: string;
}

export interface VerifyOptions {
	/** `0` disables the replay check. */
	toleranceSeconds: number;
	generic?: GenericOptions;
}

/** Providers only parse requests into this; all cryptography happens in verify.ts. */
export interface SignedRequest {
	signedPayload: Buffer;
	/** Any one of these matching is enough. */
	candidates: string[];
	algorithm: HashAlgorithm;
	encoding: SignatureEncoding;
	timestamp: number | null;
}

export type ParseResult =
	| { ok: true; request: SignedRequest }
	| { ok: false; reason: FailureReason; timestamp?: number | null };

export interface VerificationResult {
	valid: boolean;
	provider: Provider;
	reason: FailureReason | null;
	message: string | null;
	matchedSecret: 'primary' | 'secondary' | null;
	timestamp: number | null;
	verifiedAt: string;
}
