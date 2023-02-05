import { Stream } from 'stream'
import { readFile } from 'fs/promises'
import {
  randomBytes,
  createCipheriv,
  randomUUID,
  createDecipheriv,
  createHmac,
} from 'node:crypto'
import { IUsableClosable } from './using.js'
import { resolveHome } from './resolve.js'
import { IKeyStore } from '@bryopsida/key-store'

export type Data = string | Buffer
export type DataOrStream = Data | Stream

export interface KeyOpts {
  keyId: string
  rootKeyId: string
  dekContext?: string
  rootKeyContext?: string
}

export interface CipherText extends KeyOpts {
  ciphertext: DataOrStream
  iv: Buffer
  authTag?: Buffer
  algorithm: string
  context?: string
}

export interface EncryptOpts extends KeyOpts {
  plaintext: DataOrStream
  keyId: string
  iv?: Buffer
  algorithm?: string
  context?: Buffer
}

export type DecryptOpts = CipherText

export interface SealedKey {
  keyId: string
  rootKeyId?: string
  iv: Buffer
  authTag?: Buffer
  keyCipherText: Buffer
}

export interface IDataEncryptor {
  /**
   * Generate a new root key.
   * @param size key size in bytes
   * @param context Optional context used with AEAD to seal the root key. This context will be needed
   * to unseal the root key.
   * @returns A promise that resolves with the unique id for the new root key.
   */
  generateRootKey(size: number, context: string | undefined): Promise<string>

  /**
   * Generates a key and stores it somewhere and only provides a unique
   * identifier back for it for later use.
   * @param size The size of the key to generate.
   * @param rootKeyId Unique identifier of the root key that will seal the key.
   * @param rootKeyContext Optional context used with AEAD to unseal the root key, this is required if the rootKey
   * had a context provided when it was generated.
   * @param context Optional context to be used for key sealing using AEAD.
   * @returns A Promise that resolves with the unique identifier of the key.
   */
  generateDataEncKey(
    size: number,
    rootKeyId: string,
    rootKeyContext: string | undefined,
    context: string | undefined
  ): Promise<string>

  hasDataEncKey(keyId: string): Promise<boolean>
  hasRootKey(rootKeyId: string): Promise<boolean>
  validate(keyOpts: KeyOpts, message: Buffer, digest: Buffer): Promise<boolean>
  mac(keyOpts: KeyOpts, message: Buffer): Promise<Buffer>

  /**
   * Destroys a data encryption key, any data encrypted with it will be
   * lost.
   * @param keyId id of the key to destroy.
   * @returns A Promise that resolves when the key is destroyed.
   */
  destroyDataEncKey(keyId: string): Promise<void>

  /**
   * Destroys a root key, all associated data encryption keys will be lost along with their data.
   * @param rootKeyId The unique identifier of the root key to destroy.
   * @returns A Promise that resolves when the root key is destroyed.
   */
  destroyRootKey(rootKeyId: string): Promise<void>

  /**
   * Encrypt data with a data encryption key.
   * @param
   * @returns A Promise that resolves with the encrypted data, encrypted data will be returned in the form it was given with the exception
   * of String which will be a base64 encoded string.
   */
  encrypt(encryptRequest: EncryptOpts): Promise<CipherText>

  /**
   * Decrypts ciphertext accordining to the provided options
   * @param decryptOpts Options and ciphertext to decrypt.
   * @returns A Promise that resolves with the decrypted data.
   */
  decrypt(decryptOpts: DecryptOpts): Promise<Buffer | Stream | string>

  /**
   * Takes a ciphertext object and provides a base64 encoded string of the ciphertext
   * with the iv on the front (16 bytes) and the auth tag on the end (16 bytes).
   * @param cipherText The ciphertext to encode.
   * @returns A Promise that resolves with the base64 encoded ciphertext.
   */
  encodeCipherText(cipherTxt: CipherText): Promise<string>

  /**
   * Encrypts the data and encodes to a base64 string.
   * @param encryptOpts Options and ciphertext to decrypt.
   * @returns A Promise that resolves with the encrypted base64 string
   */
  encryptAndEncode(encryptOpts: EncryptOpts): Promise<string>

  /**
   * Decrypts encoded data and returns the decrypted plaintext string
   * @param encodedCipherText The encoded ciphertext to decrypt, this is base64 data encoded from
   * either the encodeCipherText or encryptAndEncode functions.
   * @param rootKeyContext value of root key context, this must match the context used to seal the key.
   * @param dekContext value of data encryption key context, this must match the context used to seal the key.
   * @param context value of context used when encrypting the ciphertext, if this doesn't match decryption will fail.
   * @returns A Promise that resolves with the decrypted plaintext string.
   */
  decryptEncoded(
    encodedCipherText: string,
    rootKeyContext: string,
    dekContext: string,
    context: string
  ): Promise<Buffer>
}

/**
 * Implements @see IDataEncryptor interface, consumes IKeyStore for distributed key persistence.
 */
export class Crypto implements IDataEncryptor, IUsableClosable {
  private readonly masterKeyPath: string
  private readonly masterKeyContext: string
  private readonly keyStore: IKeyStore

  constructor(
    keyStore: IKeyStore,
    masterKeyPath: string,
    masterKeyContext: string
  ) {
    this.masterKeyPath = masterKeyPath
    this.masterKeyContext = masterKeyContext
    this.keyStore = keyStore
  }

  encodeCipherText(cipherTxt: CipherText): Promise<string> {
    // encoding looks like
    // rootKeyId:keyId:iv:authTag:cipherText
    // context is not encoded, the decryptor must know the contexts for:
    // rootKey, key, and data, failure to provide the correct context for any one of those
    // results in decryption failure

    // get a concatenated buffer with the values.
    const concatenatedBuffer = Buffer.concat([
      Buffer.from(cipherTxt.rootKeyId), // 36 bytes
      Buffer.from(cipherTxt.keyId), // 36 bytes
      cipherTxt.iv, // 16 bytes
      cipherTxt.authTag as Buffer, // 16 bytes
      cipherTxt.ciphertext as Buffer, // cipherText.length
    ])
    return Promise.resolve(concatenatedBuffer.toString('base64'))
  }

  async encryptAndEncode(encryptOpts: EncryptOpts): Promise<string> {
    const cipherText = await this.encrypt(encryptOpts)
    return this.encodeCipherText(cipherText)
  }

  decryptEncoded(
    encodedCipherText: string,
    rootKeyContext: string,
    dekContext: string,
    context: string
  ): Promise<Buffer> {
    // first decode the buffer
    const concatenatedBuffer = Buffer.from(encodedCipherText, 'base64')
    // now pull out values
    const rootKeyId = concatenatedBuffer.slice(0, 36).toString('utf8')
    const keyId = concatenatedBuffer.slice(36, 72).toString('utf8')
    const iv = concatenatedBuffer.slice(72, 88)
    const authTag = concatenatedBuffer.slice(88, 104)
    const ciphertext = concatenatedBuffer.slice(104)
    // now we can call decrypt
    return this.decrypt({
      algorithm: 'aes-256-gcm',
      rootKeyId,
      keyId,
      iv,
      authTag,
      ciphertext,
      rootKeyContext,
      dekContext,
      context,
    }) as Promise<Buffer>
  }

  private async readFileFromPath(path: string): Promise<Buffer> {
    const buffer = await readFile(resolveHome(path), 'utf-8')
    return Buffer.from(buffer, 'base64')
  }

  private async unsealRootKey(
    keyId: string,
    keyContext: string | undefined
  ): Promise<Buffer> {
    const sealedKey = await this.keyStore.fetchSealedRootKey(keyId)
    const iv = sealedKey.slice(0, 16)
    const authTag = sealedKey.slice(sealedKey.length - 16)
    const encryptedKey = sealedKey.slice(16, sealedKey.length - 16)
    const aead = Buffer.from(
      keyContext || (await this.readFileFromPath(this.masterKeyContext))
    )

    const rootKeyDecipher = createDecipheriv(
      'aes-256-gcm',
      await this.readFileFromPath(this.masterKeyPath),
      iv,
      {
        authTagLength: 16,
      }
    )
    rootKeyDecipher.setAuthTag(authTag)
    rootKeyDecipher.setAAD(aead)

    const key = rootKeyDecipher.update(encryptedKey)
    return Buffer.concat([key, rootKeyDecipher.final()])
  }

  private async unsealDekKey(
    keyId: string,
    rootKeyId: string,
    keyContext: string | undefined,
    rootKeyContext: string | undefined
  ): Promise<Buffer> {
    const rootKey = await this.unsealRootKey(rootKeyId, rootKeyContext)
    const sealedKey = await this.keyStore.fetchSealedDataEncKey(keyId)
    const iv = sealedKey.slice(0, 16)
    const authTag = sealedKey.slice(sealedKey.length - 16)
    const encryptedKey = sealedKey.slice(16, sealedKey.length - 16)
    const keyDecipher = createDecipheriv('aes-256-gcm', rootKey, iv, {
      authTagLength: 16,
    })
    keyDecipher.setAuthTag(authTag)
    if (keyContext) {
      keyDecipher.setAAD(Buffer.from(keyContext))
    }
    const key = keyDecipher.update(encryptedKey)
    return Buffer.concat([key, keyDecipher.final()])
  }

  private async seal(
    data: Buffer,
    key: Buffer,
    context: string | undefined
  ): Promise<SealedKey> {
    const iv = randomBytes(16)
    const cipher = createCipheriv('aes-256-gcm', key, iv, {
      authTagLength: 16,
    })
    let aead
    if (context) {
      aead = Buffer.from(context)
    } else {
      aead = await this.readFileFromPath(this.masterKeyContext)
    }
    cipher.setAAD(aead)
    const ciphertext = Buffer.concat([cipher.update(data), cipher.final()])
    const authTag = cipher.getAuthTag()
    return {
      keyId: randomUUID(),
      rootKeyId: 'master',
      keyCipherText: ciphertext,
      iv,
      authTag,
    }
  }

  private async saveSealedKey(sealedKey: SealedKey): Promise<void> {
    await this.keyStore.saveSealedDataEncKey(
      sealedKey.keyId,
      Buffer.concat([
        sealedKey.iv,
        sealedKey.keyCipherText,
        sealedKey.authTag || Buffer.alloc(0),
      ])
    )
  }

  private async saveSealedRootKey(sealedKey: SealedKey): Promise<void> {
    await this.keyStore.saveSealedRootKey(
      sealedKey.keyId,
      Buffer.concat([
        sealedKey.iv,
        sealedKey.keyCipherText,
        sealedKey.authTag || Buffer.alloc(0),
      ])
    )
  }

  async generateRootKey(
    size: number,
    context: string | undefined
  ): Promise<string> {
    // use a strong random number generator to generate a key at the desired size.
    const key: Buffer = randomBytes(size)
    if (!context) {
      context = (await this.readFileFromPath(this.masterKeyContext)).toString(
        'utf-8'
      )
    }
    const sealedKey = await this.seal(
      key,
      await this.readFileFromPath(this.masterKeyPath),
      context
    )
    await this.saveSealedRootKey(sealedKey)
    return sealedKey.keyId
  }

  async generateDataEncKey(
    size: number,
    rootKeyId: string,
    rootKeyContext: string | undefined,
    dekContext: string | undefined
  ): Promise<string> {
    const key: Buffer = randomBytes(size)
    const rootKey = await this.unsealRootKey(rootKeyId, rootKeyContext)
    const sealedKey = await this.seal(key, rootKey, dekContext)
    await this.saveSealedKey(sealedKey)
    return sealedKey.keyId
  }

  async destroyDataEncKey(keyId: string): Promise<void> {
    await this.keyStore.destroySealedDataEncKey(keyId)
  }

  async destroyRootKey(rootKeyId: string): Promise<void> {
    await this.keyStore.destroySealedRootKey(rootKeyId)
  }

  async encrypt(encryptRequest: EncryptOpts): Promise<CipherText> {
    const dek = await this.unsealDekKey(
      encryptRequest.keyId,
      encryptRequest.rootKeyId,
      encryptRequest.dekContext,
      encryptRequest.rootKeyContext
    )
    const iv = encryptRequest.iv || randomBytes(16)
    const cipher = createCipheriv('aes-256-gcm', dek, iv, {
      authTagLength: 16,
    })
    if (encryptRequest.context) {
      cipher.setAAD(Buffer.from(encryptRequest.context))
    }
    if (encryptRequest.plaintext instanceof Stream) {
      const retText: CipherText = {
        keyId: encryptRequest.keyId,
        rootKeyId: encryptRequest.rootKeyId,
        iv,
        algorithm: 'aes-256-gcm',
        ciphertext: encryptRequest.plaintext.pipe(cipher).on('finish', () => {
          retText.authTag = cipher.getAuthTag()
        }),
      }
      return retText
    }
    return {
      keyId: encryptRequest.keyId,
      rootKeyId: encryptRequest.rootKeyId,
      iv,
      algorithm: 'aes-256-gcm',
      ciphertext: Buffer.concat([
        cipher.update(encryptRequest.plaintext),
        cipher.final(),
      ]),
      authTag: cipher.getAuthTag(),
    }
  }

  async decrypt(decryptOpts: CipherText): Promise<string | Buffer | Stream> {
    const dek = await this.unsealDekKey(
      decryptOpts.keyId,
      decryptOpts.rootKeyId,
      decryptOpts.dekContext,
      decryptOpts.rootKeyContext
    )
    const decipher = createDecipheriv('aes-256-gcm', dek, decryptOpts.iv, {
      authTagLength: 16,
    })
    if (decryptOpts.authTag) {
      decipher.setAuthTag(decryptOpts.authTag)
    }
    if (decryptOpts.context) {
      decipher.setAAD(Buffer.from(decryptOpts.context))
    }
    if (decryptOpts.ciphertext instanceof Stream) {
      return decryptOpts.ciphertext.pipe(decipher)
    }
    return Buffer.concat([
      decipher.update(decryptOpts.ciphertext as Buffer),
      decipher.final(),
    ])
  }

  async close(): Promise<void> {
    await this.keyStore.close()
  }

  hasDataEncKey(keyId: string): Promise<boolean> {
    return this.keyStore.hasSealedDataEncKey(keyId)
  }

  hasRootKey(rootKeyId: string): Promise<boolean> {
    return this.keyStore.hasSealedRootKey(rootKeyId)
  }

  async mac(keyOpts: KeyOpts, message: Buffer): Promise<Buffer> {
    const dek = await this.unsealDekKey(
      keyOpts.keyId,
      keyOpts.rootKeyId,
      keyOpts.dekContext,
      keyOpts.rootKeyContext
    )
    const hmac = createHmac('sha256', dek)
    // drop the cipher text
    hmac.update(message)
    const result = hmac.digest()
    return Promise.resolve(result)
  }

  async validate(
    opts: KeyOpts,
    message: Buffer,
    digest: Buffer
  ): Promise<boolean> {
    // need the dek to validate the ciphertext
    // mac is done with hmac sha256 with the dek as the secret
    return (await this.mac(opts, message)).equals(digest)
  }
}
