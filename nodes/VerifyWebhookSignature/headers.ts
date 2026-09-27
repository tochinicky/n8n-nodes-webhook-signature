import type { Headers } from './types';

export type HeaderLookup =
	| { status: 'missing' }
	| { status: 'malformed' }
	| { status: 'ok'; value: string };

export function getHeader(headers: Headers, name: string): HeaderLookup {
	const wanted = name.trim().toLowerCase();
	const key = Object.keys(headers).find((k) => k.toLowerCase() === wanted);
	const value = key === undefined ? undefined : headers[key];

	if (value === undefined || value === '') return { status: 'missing' };
	// A header sent twice arrives as an array; refuse to guess which copy to trust.
	if (Array.isArray(value)) {
		if (value.length !== 1 || typeof value[0] !== 'string') return { status: 'malformed' };
		return value[0] === '' ? { status: 'missing' } : { status: 'ok', value: value[0] };
	}
	// Headers can come from any earlier node's JSON, so don't trust the type.
	if (typeof value !== 'string') return { status: 'malformed' };
	return { status: 'ok', value };
}

export function parseTimestamp(value: string): number | null {
	const trimmed = value.trim();
	if (!/^\d{1,12}$/.test(trimmed)) return null;
	return Number(trimmed);
}
