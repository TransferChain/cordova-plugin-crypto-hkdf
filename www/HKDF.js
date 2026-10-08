const exec = require('cordova/exec')

function invalid() {
  return {
    code: 'INVALID_ARGUMENT',
    message: 'Invalid HKDF byte input or keyLength.'
  }
}

function copy(value, min, max) {
  const bytes = value instanceof ArrayBuffer ? new Uint8Array(value) : value

  if (
    !(bytes instanceof Uint8Array) ||
    !(bytes.buffer instanceof ArrayBuffer) ||
    bytes.length < min ||
    bytes.length > max
  )
    throw invalid()

  return new Uint8Array(bytes)
}

module.exports = Object.freeze({
  /** Borrow caller inputs; own exact-range binary copies until native settlement. */
  async derive({
    ikm,
    salt = new Uint8Array(),
    info = new Uint8Array(),
    keyLength = 32
  } = {}) {
    if (!Number.isInteger(keyLength) || keyLength < 1 || keyLength > 8160)
      throw invalid()

    let input, ownedSalt, ownedInfo

    try {
      input = copy(ikm, 1, 1048576)
      ownedSalt = copy(salt, 0, 65536)
      ownedInfo = copy(info, 0, 65536)
      return await new Promise((resolve, reject) => {
        exec(
          (buffer) => {
            if (
              !(buffer instanceof ArrayBuffer) ||
              buffer.byteLength !== keyLength
            ) {
              if (buffer instanceof ArrayBuffer) new Uint8Array(buffer).fill(0)

              reject({
                code: 'OPERATION_FAILED',
                message: 'Invalid native HKDF result.'
              })
              return
            }

            resolve(new Uint8Array(buffer))
          },
          reject,
          'HKDF',
          'derive',
          [{ keyLength }, input.buffer, ownedSalt.buffer, ownedInfo.buffer]
        )
      })
    } finally {
      input?.fill(0)
      ownedSalt?.fill(0)
      ownedInfo?.fill(0)
    }
  }
})
