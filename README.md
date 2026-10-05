# har-etag-audit

Find suspicious ETag behavior in a HAR response history.

The audit reports:

- one ETag associated with multiple response bodies (`etag-collision`)
- one response body associated with multiple ETags (`etag-churn`)
- `304 Not Modified` responses sent without `If-None-Match`

URLs, ETags, and bodies are represented by short SHA-256 fingerprints where needed. Query strings, ETag values, and body contents are never printed.

## Run

```bash
npx --yes github:b69ca/har-etag-audit capture.har
npx --yes github:b69ca/har-etag-audit capture.har --json --fail
```

## Options

```text
--json  emit machine-readable JSON
--fail  exit 1 when findings exist
```

The HAR is processed locally and requests are never replayed. Bodies omitted by the HAR exporter cannot be compared.

Node.js 20 or newer. No runtime dependencies.

## License

MIT
