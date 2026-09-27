# Changelog

## 0.1.0 (unreleased)

Initial release.

- **Verify Webhook Signature** node with Valid and Invalid outputs.
- Providers: Stripe (`Stripe-Signature`, multiple `v1` signatures), GitHub (`X-Hub-Signature-256`), Slack (`X-Slack-Signature` + `X-Slack-Request-Timestamp`) and Generic HMAC (SHA-1/256/512, hex/Base64, prefix, timestamp header, signed-payload template).
- Reads the raw request body from the Webhook node's binary data and reports `raw_body_missing` rather than re-serialising JSON.
- Constant-time comparison, a replay window (default 300 s) and secondary-secret rotation.
- **Webhook Signing Secret API** credential with a local check for empty secrets and stray whitespace.
