<!--
SPDX-FileCopyrightText: 2022 Mix Irving

SPDX-License-Identifier: CC-BY-4.0
-->

# ssb-meta-feeds-dm-spec

Version: 0.1

Author: Mix Irving <mix@protozoa.nz>

License: This work is licensed under a Creative Commons Attribution 4.0 International License.

## Abstract

The addition of metafeeds (see [ssb-meta-feeds-spec]), means that the process of encrypting messages
to other peers as direct messages (DMs) now unclear.

In classic scuttlebutt, when you see a `recps` (recipients) field which contains a feedId, you would
know that meant to calculate a shared cryptographic key by:
1. converting the feedId from a public ed25519 signing key to a curve25519 encryption key
2. converting your feedIds ed25519 signing secret key to curve25519 encryption key
3. creating a Diffie-Hellman shared key by crossing your secret with their public encryption keys

With metafeeds, we need to define which "feed" or "identity" keys we want to put in the `recps`, 
and how we should derive a shared encryption key given we are dealing with trees of keys.

## Definitions

- **DM** - a "direct message", in this context a message encrypted so that one (or more) other peers can read it.
- **Root feed** - the top-most feed in a peers metafeed tree
- **Leaf feed** - a leaf feed is feed at the bottom of a metafeed tree, and contains content (i.e. not link to further sub-feeds)
- **Mirror leaf** - if two peers both have a _leaf feeds_ which were determinstically placed in the same position in their respective metafeed trees, we call these "mirror leaves".
    - this spec follows the v1 tree structure specified in [ssb-meta-feeds-spec]

    ```mermaid
    flowchart TB

    subgraph mix
      direction TB

      1_root[root] -->
      1_v1[v1] -->
      1_shard[D] -->
      1_leaf[chess]:::leaf
    end

    subgraph staltz
      direction TB

      2_root[root] -->
      2_v1[v1] -->
      2_shard[4] -->
      2_leaf[chess]:::leaf
    end

    classDef leaf fill:hotpink, stroke:none;
    classDef cluster fill:#ddd, stroke:none;
    ```
    _Diagram showing two peers who have mirror "chess" leaves. Note that under v1 metafeed trees, the shard will likely be different but is deterministically deriveable._



- **DH Keys** - short for [Diffie-Hellman](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange) curve25519 keys. A public-private keypair that can be used to derived shared cryptographic keys through a special "multiplication" with another peer.


## 1. Announcing DH-keys

This spec only supports sending a DM from one leaf to its mirror leaf feed.

To signal that you support DMs, when you publish the `meta/add/derived` announcing your leaf feed,
you attach the metadata containing a public key for encryption.

```js
{
  type: 'meta/add/derived',
  purpose: 'chess',
  subfeed: 'ssb:feed/classic/DIoOBMaI1f0mJg+5tUzZ7vgzCeeHh8+zGta4pOjc+k0='
  metadata: {
    encryption: {
      curve: 'curve25519',
      public: 'BtFRgQLgXyq3G48jDrX9OaY/mnPaWnu+kOfx2yEOWwU=' // public DH key
    }
  }
}
```

- **1.1** Feeds supporting DMs MUST include a public curve25519 key on the `meta/add/derived` message connecting the leaf feed to it's shared
    - this public key MUST be stored in the message content, under `metadata.encryption.public`
    - the message MUST announce the curve used as `curve25519` under `metadata.encryption.curve`
    - _you will need to persist, or have a strategy for recalling the private part for yourself_
- **1.2** If a feed does not announce a public key this way you SHOULD NOT DM it


## 2. Encrypting a DM message

If I (mix) am sending a DM to a friend (staltz) I'm playing chess with, I do that by publishing 
a message like the following to my `chess` leaf feed:

```javascript
{
  type: 'chess/move',
  // ...
  recps: [
    'ssb:feed/bendybutt-v1/mreYjjsak8sIXIzVq/LPVugxXYDZTAszN6aOrHgbtL8=', // mix
    'ssb:feed/bendybutt-v1/UkrcQFhPcOMgW5Ag6iuXdawHO6ArRmpueeINt/X4MGA='  // staltz
  ]
}
```

- **2.1** DM encrypted messages MUST contain a `recps` array which
    - a) MUST include ssb-uri encoded Root feed ids of all peers involved in the DM
        - <details>
          <summary>Why Root feed ids? (see more)</summary>
          When referencing another person, we want a unique id, which their Root feed Id is.
          We also want other recipients to be able to know who to replicate if they discover a recipient they don't already have. The Root feed id allows them to more easily do this.
        </details>
        
        - <details>
          <summary>Why include yourself? (see more)</summary>
          For most encrypted message, we want to peers to be able to reply simple by copying 
          the `recps` from the initial message and those should "just work".
          Including `recps` is also a good way to transparently signal who else can open this
          (there may be up to 16 recipients, yourself included)
        </details>
    - b) MAY include other ids (e.g. group, po-box)
    
- **2.2** the ciphertext MUST be derived by following the [envelope-spec]
- **2.3** the `{ key, scheme }` pairs used for encryption MUST be deived by mapping the message `recps`
  - a) for a feed id that's **not** ours:
    - i) `scheme` MUST be equal to `envelope-id-based-meta-feeds-dm-curve2519`
    - ii) `key` MUST be derived by combining mirror leaf feed ids along with the associated DH keys as follows:
    ```js
    const hash = 'SHA256'
    const length = 32
    const salt = SHA256('envelope-dm-v1-extract-salt')

    function directMessageSlotKey(
      my_dh_secret,
      my_dh_public,
      my_id_bfe,
      your_dh_public,
      your_id_bfe
    ) {
      var input_keying_material = scalarmult(my_dh_secret, your_dh_public)

      var info_context = Buffer.from('envelope-ssb-dm-v1/key', 'utf8')
      var info_keys = sort([
        bfe.encode(3, 0, my_dh_public) || my_id_bfe,
        bfe.encode(3, 0, your_dh_public) || your_id_bfe
      ])
      var info = slp.encode([info_context, ...info_keys])

      return hkdf(input_keying_material, length, { salt, info, hash })
    }
    ```

    - `(dh_secret, dh_public)` are the secret and public parts of a Diffie-Hellman keypair
    - `id_bfe` is the "id" of a feed, namely the public part of that feed's signing keypair, encoded in "type-format-key" format (see [BFE])
    - `||` means Buffer concat
    - `sort` means sort these 2 buffers bytewise so that the smallest is first
    - `bfe.encode` is bfe encoding of the encryption key, here with `type: 3, format 0` (see [BFE])
    - `slp.encode` is "shallow length-prefixed encode" (see [SLP])
  - b) for a feed id that IS yours, see this the "self case" [here in the private-group-spec](https://github.com/ssbc/private-group-spec/blob/master/direct-messages/README.md#b-self-case---mapping-our-own-feed_id-to-recp_key)
  - c) for a group id, or P.O. box id, see the [private-group-spec]

- **2.4** any failure to map a recipient MUST result in an encryption failure 






<!-- Refereneces -->

[ssb-meta-feeds-spec]: https://github.com/ssbc/ssb-meta-feeds-spec
[envelope-spec]: https://github.com/ssbc/envelope-spec
[private-group-spec]: https://github.com/ssbc/private-group-spec
[slp]: https://github.com/ssbc/envelope-spec/blob/master/encoding/slp.md
[bfe]: https://github.com/ssb-ngi-pointer/ssb-bfe-spec
