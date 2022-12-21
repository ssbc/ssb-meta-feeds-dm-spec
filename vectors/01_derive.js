const test = require('tape')
const sodium = require('sodium-native')
const crypto = require('crypto')
const hkdf = require('futoin-hkdf')
const fs = require('fs')
const path = require('path')

const SECRET_KEY_LENGTH = sodium.crypto_scalarmult_SCALARBYTES // 32
const PUBLIC_KEY_LENGTH = sodium.crypto_scalarmult_BYTES // 32

test('deriveDiffieHellmanKeys', t => {
  const seed = crypto.randomBytes(32)
  const nonce = crypto.randomBytes(32)
  const keys = deriveDiffieHellmanKeys(seed, nonce)

  const keysSame = deriveDiffieHellmanKeys(seed, nonce)
  t.deepEqual(keys.secret, keysSame.secret, 'deterministic derivation (secret key)')
  t.deepEqual(keys.public, keysSame.public, 'deterministic derivation (public key)')

  const seed2 = crypto.randomBytes(32)
  const nonce2 = crypto.randomBytes(32)
  const keys2 = deriveDiffieHellmanKeys(seed2, nonce2)

  t.deepEqual(
    scalarMult(keys.secret, keys2.public),
    scalarMult(keys2.secret, keys.public),
    'scalar_mult creates shared key'
  )

  const output = {
    type: 'meta_feeds_direct_message_derived',
    description: 'calculate a curve25519 keypair from a seed and nonce',
    input: {
      seed: seed.toString('base64'),
      nonce: nonce.toString('base64')
    },
    output: {
      secret: keys.secret.toString('base64'),
      public: keys.public.toString('base64')
    }
  }

  fs.writeFileSync(
    path.join(__dirname, '01_derive.json'),
    JSON.stringify(output, null, 2)
  )

  t.end()
})

//

function deriveDiffieHellmanKeys (seed, nonce) {
  const secret_key = hkdf(seed, SECRET_KEY_LENGTH, {
    salt: 'ssb',
    info: 'ssb-meta-feeds-dm-v1:' + nonce,
    hash: 'SHA-256'
  })

  const public_key = Buffer.alloc(PUBLIC_KEY_LENGTH)
  sodium.crypto_scalarmult_base(public_key, secret_key)

  return {
    secret: secret_key,
    public: public_key
  }
}

function scalarMult (secret_key, public_key) {
  const shared_key = Buffer.alloc(sodium.crypto_scalarmult_BYTES)

  sodium.crypto_scalarmult(shared_key, secret_key, public_key)
  return shared_key
}
