import type { Headers } from './types';

export type HeaderLookup =
	| { status: 'missing' }
	| { status: 'malformed' }
	| { status: 'ok'; value: string };

/**
 * Case-insensitive header lookup. HTTP header names are case-insensitive, and
 * n8n lowercases them, but a user may type `Stripe-Signature` in a parameter.
 *
 * A header sent more than once arrives as an array. We refuse to pick one,
 * because choosing which copy to trust is exactly what an attacker would like
 * to influence.
 */
export function getHeader(headers: Headers, name: string): HeaderLookup {
	const wanted = name.trim().toLowerCase();
	const key = Object.keys(headers).find((k) => k.toLowerCase() === wanted);
	const value = key === undefined ? undefined : headers[key];

	if (value === undefined || value === '') return { status: 'missing' };
	if (Array.isArray(value)) {
		if (value.length !== 1 || typeof value[0] !== 'string') return { status: 'malformed' };
		return value[0] === '' ? { status: 'missing' } : { status: 'ok', value: value[0] };
	}
	// Headers can come from any earlier node's JSON, so don't trust the type.
	if (typeof value !== 'string') return { status: 'malformed' };
	return { status: 'ok', value };
}

/** Parses a Unix-seconds timestamp. Anything other than plain digits is rejected. */
export function parseTimestamp(value: string): number | null {
	const trimmed = value.trim();
	if (!/^\d{1,12}$/.test(trimmed)) return null;
	return Number(trimmed);
}
