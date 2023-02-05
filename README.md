# Crypto

[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=bryopsida_crypto&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=bryopsida_crypto) [![Coverage](https://sonarcloud.io/api/project_badges/measure?project=bryopsida_crypto&metric=coverage)](https://sonarcloud.io/summary/new_code?id=bryopsida_crypto) [![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=bryopsida_crypto&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=bryopsida_crypto) [![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=bryopsida_crypto&metric=vulnerabilities)](https://sonarcloud.io/summary/new_code?id=bryopsida_crypto) [![Code Smells](https://sonarcloud.io/api/project_badges/measure?project=bryopsida_crypto&metric=code_smells)](https://sonarcloud.io/summary/new_code?id=bryopsida_crypto) [![Bugs](https://sonarcloud.io/api/project_badges/measure?project=bryopsida_crypto&metric=bugs)](https://sonarcloud.io/summary/new_code?id=bryopsida_crypto)

## What is this?

A library to faciliate using data encryption keys as well as do some light encryption/decryption.

## How do I use this?

```typescript
import { randomBytes, randomUUID } from 'crypto'
import { tmpdir } from 'os'
import { FileKeyStore, IKeyStore } from '@bryopsida/key-store'
import { IDataEncryptor, EncryptOpts, Crypto } from '../src/crypto'
import { writeFile } from 'fs/promises'
import { describe, expect, it, beforeEach } from '@jest/globals'

//setup a key store, in this case on the file system
const key = randomBytes(32)
const salt = randomBytes(16)
const context = randomBytes(32)
const masterKey = randomBytes(32).toString('base64')
const masterSalt = randomBytes(16).toString('base64')
const masterKeyFile = randomUUID()
const masterSaltFile = randomUUID()
const storeDir = tmpdir()
const keyStoreDir = randomUUID()
await writeFile(`${storeDir}/${masterKeyFile}`, masterKey)
await writeFile(`${storeDir}/${masterSaltFile}`, masterSalt)
keyStore = new FileKeyStore(
  `${storeDir}/${keyStoreDir}`,
  () => Promise.resolve(key),
  () => Promise.resolve(salt),
  () => Promise.resolve(context)
)

// now we can make the crypto instance
crypto = new Crypto(
  keyStore,
  `${storeDir}/${masterKeyFile}`,
  `${storeDir}/${masterSaltFile}`
)

// an example of encrypting to a encoded value and decrypting
it('can encrypt and decrypted encoded text', async () => {
  const rootKeyId = await crypto.generateRootKey(32, 'encoded-test')
  const dek = await crypto.generateDataEncKey(
    32,
    rootKeyId,
    'encoded-test',
    'dek'
  )
  const encryptedData = await crypto.encryptAndEncode({
    plaintext: Buffer.from('test-data'),
    keyId: dek,
    rootKeyId,
    rootKeyContext: 'encoded-test',
    dekContext: 'dek',
    context: Buffer.from('data-context'),
  })
  const plainText = (
    await crypto.decryptEncoded(
      encryptedData,
      'encoded-test',
      'dek',
      'data-context'
    )
  ).toString('utf8')
  expect(plainText).toEqual('test-data')
})
```
