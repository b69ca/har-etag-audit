import test from 'node:test';
import assert from 'node:assert/strict';
import { analyze } from '../src/index.js';
const entry = (etag, body, status = 200, requestHeaders = []) => ({ request: { method: 'GET', url: 'https://api.test/item?token=secret', headers: requestHeaders }, response: { status, headers: etag == null ? [] : [{ name: 'ETag', value: etag }], content: body == null ? {} : { text: body } } });
test('finds one etag for different bodies', () => { const r = analyze({ log: { entries: [entry('"v1"', 'a'), entry('"v1"', 'b')] } }); assert.equal(r.findings[0].type, 'etag-collision'); });
test('finds different etags for one body', () => { const r = analyze({ log: { entries: [entry('"v1"', 'same'), entry('"v2"', 'same')] } }); assert.equal(r.findings[0].type, 'etag-churn'); });
test('finds unconditional 304 responses', () => { const r = analyze({ log: { entries: [entry('"v1"', null, 304)] } }); assert.equal(r.findings[0].type, 'unconditional-304'); });
test('does not expose bodies, etags, or queries', () => { const r = analyze({ log: { entries: [entry('super-secret-etag', 'private-body'), entry('super-secret-etag', 'other')] } }); const text = JSON.stringify(r); assert.equal(text.includes('private-body') || text.includes('super-secret-etag') || text.includes('token=secret'), false); });
