# shamir-secret-sharing-store

![Github CI](https://github.com/0xjjpa/shamir-secret-sharing-store/workflows/Github%20CI/badge.svg)

TypeScript library to generate metadata-rich Shamir's Secret Share stores for data transfer, based on [Privy’s implementation](https://github.com/privy-io/shamir-secret-sharing) of [Shamir's Secret Sharing algorithm](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing).

Only supported in browser environments.


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