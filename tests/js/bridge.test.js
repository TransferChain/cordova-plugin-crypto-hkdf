import assert from 'node:assert/strict'
import { hkdfSync } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { runInNewContext } from 'node:vm'
import { it } from 'mocha'

function plugin(exec) {
  const module = { exports: {} }

  runInNewContext(
    readFileSync(new URL('../../www/HKDF.js', import.meta.url), 'utf8'),
    {
      module,
      Uint8Array,
      ArrayBuffer,
      require(name) {
        assert.equal(name, 'cordova/exec')
        return exec
      }
    }
  )
  return module.exports
}

const hex = (value) => new Uint8Array(Buffer.from(value, 'hex')),
  vectorOne =
    '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865',
  vectorEmpty =
    '8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8',
  fixture = () => ({
    ikm: new Uint8Array(22).fill(11),
    salt: hex('000102030405060708090a0b0c'),
    info: hex('f0f1f2f3f4f5f6f7f8f9'),
    keyLength: 42
  })

it('transfers exact binary ranges and RFC5869 vectors through the Cordova JS boundary', async () => {
  const owned = [],
    api = plugin((success, _reject, service, action, args) => {
      assert.equal(service, 'HKDF')
      assert.equal(action, 'derive')
      owned.push(...args.slice(1).map((buffer) => new Uint8Array(buffer)))
      success(
        hkdfSync(
          'sha256',
          ...args.slice(1).map((buffer) => new Uint8Array(buffer)),
          args[0].keyLength
        )
      )
    }),
    caller = fixture(),
    first = await api.derive(caller),
    empty = await api.derive({ ikm: caller.ikm, keyLength: 42 })

  assert.equal(Buffer.from(first).toString('hex'), vectorOne)
  assert.equal(Buffer.from(empty).toString('hex'), vectorEmpty)
  assert.ok(caller.ikm.every((value) => value === 11))
  assert.ok(owned.every((bytes) => bytes.every((value) => value === 0)))
  first.fill(0)
  empty.fill(0)
  const backing = new Uint8Array([99, 1, 2, 88]),
    sliced = await api.derive({ ikm: backing.subarray(1, 3), keyLength: 1 })

  assert.deepEqual([...backing], [99, 1, 2, 88])
  assert.equal(sliced.length, 1)
  sliced.fill(0)
})

it('bounds lengths and rejects malformed binary before native dispatch', async () => {
  let calls = 0

  const api = plugin((success, _reject, _service, _action, args) => {
    calls++
    success(new ArrayBuffer(args[0].keyLength))
  })

  for (const keyLength of [0, -1, 8161, 1.5, NaN, Infinity, '32']) {
    await assert.rejects(api.derive({ ...fixture(), keyLength }))
  }

  for (const value of [
    null,
    {},
    [],
    'bytes',
    new DataView(new ArrayBuffer(2)),
    new Uint8Array()
  ]) {
    await assert.rejects(api.derive({ ...fixture(), ikm: value }))
  }

  await assert.rejects(api.derive({ ...fixture(), salt: 'invalid' }))
  await assert.rejects(api.derive({ ...fixture(), info: [] }))
  assert.equal(calls, 0)
  for (const keyLength of [1, 32, 8160]) {
    const result = await api.derive({ ...fixture(), keyLength })

    assert.equal(result.length, keyLength)
    result.fill(0)
  }
})

it('cleans input copies after native failure and isolates overlapping requests', async () => {
  const requests = [],
    api = plugin((success, reject, _service, _action, args) =>
      requests.push({
        success,
        reject,
        bytes: args.slice(1).map((buffer) => new Uint8Array(buffer))
      })
    ),
    caller = fixture(),
    first = api.derive(caller),
    second = api.derive(caller),
    rejected = assert.rejects(second)

  assert.notEqual(requests[0].bytes[0].buffer, requests[1].bytes[0].buffer)
  requests[0].success(new ArrayBuffer(42))
  const result = await first

  assert.ok(
    requests[0].bytes.every((bytes) => bytes.every((value) => value === 0))
  )
  assert.ok(requests[1].bytes[0].every((value) => value === 11))
  requests[1].reject({ code: 'OPERATION_FAILED', message: 'Synthetic failure' })
  await rejected
  assert.ok(
    requests[1].bytes.every((bytes) => bytes.every((value) => value === 0))
  )
  assert.ok(caller.ikm.every((value) => value === 11))
  result.fill(0)
})

it('rejects malformed native output and wipes its owned bytes', async () => {
  const malformed = new Uint8Array(31).fill(7),
    api = plugin((success) => success(malformed.buffer))

  await assert.rejects(api.derive({ ...fixture(), keyLength: 32 }))
  assert.ok(malformed.every((value) => value === 0))
})
