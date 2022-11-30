# Derived DM Keys

The ssb-meta-feeds-spec defines how and where to announce the public part of your DM keys
for particular leaf feeds, but this leaves you with the challenge of how and where to persist
the private parts of those keys.

This sub-spec defines a way to deterministically derive your DM keys from your meta-feed seed.

1. When announcing a leaf feed, we generate a `nonce` (32 bytes of random data)
2. We combine this with our `seed` using HKDF to generate a curve25519 keypair
3. we publish the public key AND the `nonce` in the announce message metadata
  ```js
  {
    type: 'meta/add/derived',
    purpose: 'chess',
    subfeed: 'ssb:feed/classic/DIoOBMaI1f0mJg+5tUzZ7vgzCeeHh8+zGta4pOjc+k0='
    metadata: {
      nonce: '9OaY/mnPaWnu+kOfxBtFRgQLgXyq3X2yEOW48jDrw='
      encryption: {
        curve: 'curve25519',
        public: 'BtFRgQLgXyq3G48jDrX9OaY/mnPaWnu+kOfx2yEOWwU='
      }
    }
  }
  ```

## 1. Deriving an encryption key

```js
const nonce = crypto.randomBytes(32)

function deriveDiffieHellmanKeys (seed, nonce) {

  return hkdf.expand(
}
```


