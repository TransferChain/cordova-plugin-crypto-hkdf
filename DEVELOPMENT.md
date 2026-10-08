# Native HKDF-SHA256 development

This plugin derives bytes from high-entropy input using RFC 5869 extract and
expand. It is not a password stretching function.

## Plugin entry point

After Cordova deviceready, call
`CryptoKit.HKDF.derive({ ikm, salt, info, keyLength })`. The returned Promise
resolves to a Uint8Array. Salt and info default to empty byte arrays; keyLength
defaults to 32. Choose info to separate different uses of derived keys. The
plugin does not define a database record format.

Android executes on Cordova's thread pool using HmacSHA256; iOS uses Cordova's
background dispatch and CryptoKit. Independent requests may overlap; the caller
controls admission and its total memory budget.

## Binary and ownership contract

The plugin facade accepts Uint8Array or ArrayBuffer input. It copies the exact
view range, preserving caller ownership, and delegates binary serialization to
Cordova. IKM is limited to 1–1048576 bytes; salt and info to 0–65536 bytes each.
Output is 1–8160 bytes, the RFC SHA-256 expansion limit of 255 blocks.

Android uses javax.crypto.Mac with HmacSHA256. Extraction produces a temporary
PRK; expansion feeds the previous block, info, and one-byte counter into HMAC.
An empty salt is equivalent to 32 zero bytes. Intermediate arrays and owned
bridge buffers are wiped in finally. iOS uses CryptoKit HKDF<SHA256> and clears
owned Data buffers on exit. Cordova serializes the callback result before the
native output is cleared.

Successful output belongs to the caller. Wipe owned derived bytes in finally
after all dependent asynchronous operations have settled. Wrong length native
output is rejected and cleared. Errors contain fixed diagnostic text, never key
material. Native provider and bridge internal copies are not covered by a
complete memory-erasure guarantee.

## Validation

[Bridge tests](tests/js/bridge.test.js) cover RFC vectors, bounds, exact-view
ownership and rejected-result cleanup using Cordova mocks. Native Java and Swift
tests are under tests/native, tests/android and tests/ios. See
[test setup](docs/TESTING.md) for harness requirements and validation limits.
