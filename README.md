# shamir-secret-sharing-store

![Github CI](https://github.com/0xjjpa/shamir-secret-sharing-store/workflows/Github%20CI/badge.svg)

TypeScript library to generate metadata-rich Shamir's Secret Share stores for data transfer, based on [Privy’s implementation](https://github.com/privy-io/shamir-secret-sharing) of [Shamir's Secret Sharing algorithm](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing).

Only supported in browser environments.

## Background

Splitting a secret via the Shamir Secret Sharing schema is an extremely useful way to distribute and delegate a secret. However, there's no format for meaningful metadata of a share. This project suggest the introduction of a [keystore](https://goethereumbook.org/keystore/)-like format that can be used to provide meaningful metadata to the share generated, instead of the plain `Buffer`-like representation. In the same way that a traditional crypto private key benefits from being stored into a keystore, a secret share would benefit of metadata describing the data that it's trying to protect without disclosing the actual data.

### Motivation

Although one can argue that the lack of metadata for the secret to encrypt is a feature and not a bug, the storage, operation and usage of blobs of shares can become cumbersome after some time. In short, `080198161f3f4aa4cc91d5a16d7cdf47db3cb3b1b8640457fa3892701a65b665307c` gives you little to no information which can later be used for rotation or maintenance.

From an operational point of view, looking to these sort of strings in isolation will always required an additional piece of information (e.g. a relational table) to be able to piece together the purpose of the secret the share protects. Losing the relational data can be tricky, specially in the context of digital assets, where compliance to AML/KYC laws might require the removal of shares used as backups for restricted individuals.

In other words, if a crypto address is blacklisted by OFAC (or other similar organisations), and a share related to the respective private key controlling this address, it could be argued that the retainer of these backups could be sanctioned by simply storing this share. By adding metadata, we can guarantee plausible deniability and implement checks in place to trigger automatic systems whenever accounts are flagged.

### Schema (Zod)


```typescript
const cryptoParamsSchema = z.object({
  ciphertext: z.string(),
  cipherparams: z.object({
    iv: z.string(),
    name: z.string(),
    length: z.number(),
  }),
  kdf: z.string(),
  kdfparams: z.object({
    salt: z.string(),
    iterations: z.number(),
    hash: z.string(),
  }),
});

export const shareSchema = z.object({
  version: z.number(),
  id: z.string(),
  share: z.object({
    total: z.number(),
    threshold: z.number(),
    encrypted: z.boolean(),
    share_sha512: z.string(),
    secret_sha512: z.string(),
  }),
  crypto: cryptoParamsSchema,
  algorithm: z.string(),
});

```

### Diagram

![Paper Blockchain 52](https://github.com/privy-io/shamir-secret-sharing/assets/1128312/12c1f650-97de-4693-9d85-10d81a2300b3)


## Usage

We can `splitWithPasswordAsStore` a secret into shares with a password, and later `decryptAndCombineWithPassword` the shares to reconstruct the secret. Unlike the `shamir-secret-sharing` original package, this package includes metadata of both the secret and encrypted share to
facilitate the management and storage of the shamir secrets.

```typescript
import {splitWithPasswordAsStore, decryptAndCombineWithPassword} from 'shamir-secret-sharing-store';

const encryptedShares = await splitWithPasswordAsStore("my secret","password",3,2);
const combinedSecret = await decryptAndCombineWithPassword("password",encryptedShares);
```

Example of a generated secret share:

```
{
    version: 1,
    id: '47beb1f7-7c1c-4b4c-be76-fca27e5f2cd7',
    share: {
        total: 3,
        threshold: 2,
        encrypted: true,
        contents: '42e3997cf776e75840bbac7b51107b6e117009f4c9ebe3',
        share_sha512: '44631f1fd6b9d0aa824e9a0342210466fc73ad569d562a2266f7bb57d1f731fd16b98a308bf6131b8bd3574a5c23d935c3079baeab95c030bfe2087454829bb1',
        secret_sha512: 'bdbcba12c7745e080d984546d23c29f0a8bf9f95968958a39e77062c93ef9a1fd7d318e5d3fb9d41d358b8678dd5b75070ab21aecaab88c563c3b8189e2d1c74'
    },
    crypto: {
        ciphertext: '42e3997cf776e75840bbac7b51107b6e117009f4c9ebe3',
        cipherparams: [Object],
        kdf: 'PBKDF2',
        kdfparams: [Object]
    },
    algorithm: 'shamir-secret-sharing'
}
```

## API

This package exposes two functions: `splitWithPasswordAsStore` and `decryptAndCombineWithPassword`.

#### splitWithPasswordAsStore

```ts
/**
 * Splits a `secret` string into encrypted shares using a `password` for encryption. It first splits the secret and then encrypts each share with the given password.
 * 
 * @param secret The secret string to be split and encrypted into shares.
 * @param password The password used for encrypting the shares.
 * @param total The total number of shares to split `secret` into. Must be a positive integer.
 * @param threshold The minimum number of shares required to reconstruct the original `secret`. Must be a positive integer.
 * @returns A list of encrypted shares.
 */
declare function splitWithPasswordAsStore(
  secret: string,
  password: string,
  total: number,
  threshold: number,
): Promise<Share[]>;
```

#### decryptAndCombineWithPassword

```ts
/**
 * Decrypts a list of shares using a given `password` and then combines them to reconstruct the original secret.
 * 
 * @param password The password used for decrypting the shares.
 * @param shares An array of encrypted shares.
 * @returns The decrypted and combined secret as a string.
 */
declare function decryptAndCombineWithPassword(
  password: string,
  shares: Share[],
): Promise<string>;
```

## License

Apache-2.0. See the [license file](LICENSE).