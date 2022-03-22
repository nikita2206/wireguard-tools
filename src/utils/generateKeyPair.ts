import { generatePresharedKey, generatePrivateKey, generatePublicKey } from "./wg-crypto";

interface Options {
  preSharedKey: boolean
  privateKey?: string
}

/** 
 * Generate a key pair using wg
 * optionally also generate a PreSharedKey
 */
export const generateKeyPair = async (opts?: Options) => {
  // Make the private and public key pair

  const privateKey = opts?.privateKey ? new Uint8Array(Buffer.from(opts?.privateKey, "base64")) : generatePrivateKey()
  const publicKey = generatePublicKey(privateKey)

  const preSharedKey = opts?.preSharedKey ? (Buffer.from(generatePresharedKey()).toString("base64")) : undefined

  return {
    privateKey: privateKey,
    publicKey: publicKey,
    preSharedKey: preSharedKey
  }
}
