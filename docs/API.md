# Usage and API

All examples run inside an async function after Cordova `deviceready`. They call
the public JavaScript module registered by plugin.xml. Consumer functions such
as consumeKey are placeholders supplied by the caller.

## Interface

`CryptoKit.HKDF.derive({ ikm, salt, info, keyLength })` returns
Promise<Uint8Array>. IKM is high-entropy input, not a human password.

| Field     | Contract                                           |
| --------- | -------------------------------------------------- |
| ikm       | Uint8Array or ArrayBuffer, 1–1048576 bytes         |
| salt      | Optional bytes, 0–65536 bytes; omitted means empty |
| info      | Optional domain-separation bytes, 0–65536 bytes    |
| keyLength | Integer 1–8160 bytes; default 32                   |

```js
const info = new TextEncoder().encode('example/application-key/v1'),
  salt = await CryptoKit.Random.randomBytes(16)
let key
try {
  key = await CryptoKit.HKDF.derive({ ikm, salt, info, keyLength: 32 })
  await consumeKey(key)
} finally {
  key?.fill(0)
  salt.fill(0)
}
```

ikm is caller-owned input; consumeKey is your consumer. Random is a separate
plugin in this example. HKDF snapshots exact input views and wipes owned input
copies after native settlement. The caller owns successful output. Empty salt
has RFC 5869 semantics; it does not create entropy absent from IKM.

## Errors and lifecycle

Handle rejected promises or failure callbacks explicitly. Do not substitute
plaintext, predictable keys or weaker algorithms after failure. Keep caller
buffers valid until async work completes, and wipe only buffers you own.

[Developer guide](../DEVELOPMENT.md) · [Security policy](../SECURITY.md) ·
[README](../README.md)
