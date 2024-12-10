'use strict'

/** ******* Imports ********/

const {
  /* The following functions are all of the cryptographic
  primatives that you should need for this assignment.
  See lib.js for details on usage. */
  bufferToString,
  genRandomSalt,
  generateEG, // async
  computeDH, // async
  verifyWithECDSA, // async
  HMACtoAESKey, // async
  HMACtoHMACKey, // async
  HKDF, // async
  encryptWithGCM, // async
  decryptWithGCM,
  cryptoKeyToJSON, // async
  govEncryptionDataStr
} = require('./lib')

/** ******* Implementation ********/

class MessengerClient {
  constructor (certAuthorityPublicKey, govPublicKey) {
    // the certificate authority DSA public key is used to
    // verify the authenticity and integrity of certificates
    // of other users (see handout and receiveCertificate)
    // you can store data as needed in these objects.
    // Feel free to modify their structure as you see fit.
    this.caPublicKey = certAuthorityPublicKey
    this.govPublicKey = govPublicKey
    this.conns = {} // data for each active connection
    this.certs = {} // certificates of other users
    this.EGKeyPair = null // keypair from generateCertificate
  }

  /**
   * Generate a certificate to be stored with the certificate authority.
   * The certificate must contain the field "username".
   *
   * Arguments:
   *   username: string
   *
   * Return Type: certificate object/dictionary
   */
  async generateCertificate (username) {
    const keypairObject = await generateEG()
    this.EGKeyPair = keypairObject

    const certificate = {
      username,
      pub: keypairObject.pub
    }

    return certificate
  }

  /**
 * Receive and store another user's certificate.
 *
 * Arguments:
 *   certificate: certificate object/dictionary
 *   signature: string
 *
 * Return Type: void
 */
  async receiveCertificate (certificate, signature) {
  // The signature will be on the output of stringifying the certificate
  // rather than on the certificate directly.
    const certString = JSON.stringify(certificate)
    const valid = await verifyWithECDSA(this.caPublicKey, certString, signature)
    if (valid) {
      this.certs[certificate.username] = certificate
    } else {
      throw ('Tampered certificate!')
    }
  }

  /**
 * Generate the message to be sent to another user.
 *
 * Arguments:
 *   name: string
 *   plaintext: string
 *
 * Return Type: Tuple of [dictionary, string]
 */
  async sendMessage (name, plaintext) {
    const cert = this.certs[name]

    if (!(name in this.conns)) {
      const rootkey = await computeDH(this.EGKeyPair.sec, cert.pub)
      const connState = {
        keypair: this.EGKeyPair,
        next_root: rootkey,
        recv_root: null,
        prev_recv_root: null,
        send_root: null,
        recv_pub: cert.pub,
        curr_sender: false,
        send_cnt: 0,
        recv_cnt: 0,
        prev_recv_cnt: 0,
        skipped: {}
      }
      this.conns[name] = connState
    }

    const connState = this.conns[name]
    let send_cnt = connState.send_cnt
    if (!connState.curr_sender) {
      const keypair = await generateEG()
      const computedDH = await computeDH(keypair.sec, connState.recv_pub)
      const [next_root, send_root] = await HKDF(connState.next_root, computedDH, 'ratchet-str')
      connState.keypair = keypair
      connState.next_root = next_root
      connState.send_root = send_root
      connState.curr_sender = true
      send_cnt = 0
    }

    const AES_key = await HMACtoAESKey(connState.send_root, 'AES')
    connState.send_root = await HMACtoHMACKey(connState.send_root, 'HMAC')
    connState.send_cnt = send_cnt + 1

    const ivGov = genRandomSalt()
    const govkeypair = await generateEG()
    const govDH = await computeDH(govkeypair.sec, this.govPublicKey)
    const govAES = await HMACtoAESKey(govDH, govEncryptionDataStr)
    const keyJSON = await cryptoKeyToJSON(AES_key)
    const cGov = await encryptWithGCM(govAES, Buffer.from(keyJSON.k, 'base64'), ivGov)

    const salt = genRandomSalt()

    const header = {
      pub: connState.keypair.pub,
      vGov: govkeypair.pub,
      cGov,
      ivGov,
      receiverIV: salt,
      send_cnt
    }

    // encrypt
    const header_string = JSON.stringify(header)
    const ciphertext = await encryptWithGCM(AES_key, plaintext, salt, header_string)
    return [header, ciphertext]
  }

  /**
 * Decrypt a message received from another user.
 *
 * Arguments:
 *   name: string
 *   [header, ciphertext]: Tuple of [dictionary, string]
 *
 * Return Type: string
 */
  async receiveMessage (name, [header, ciphertext]) {
    const cert = this.certs[name]

    if (!(name in this.conns)) {
      const rootkey = await computeDH(this.EGKeyPair.sec, cert.pub)

      const connState = {
        keypair: this.EGKeyPair,
        next_root: rootkey,
        recv_root: null,
        prev_recv_root: null,
        send_root: null,
        recv_pub: cert.pub,
        curr_sender: true,
        send_cnt: 0,
        recv_cnt: 0,
        prev_recv_cnt: 0,
        skipped: {}
      }
      this.conns[name] = connState
    }

    const connState = this.conns[name]
    let recv_cnt = connState.recv_cnt
    if (connState.curr_sender) {
      if (connState.recv_pub != header.pub) {
        const computedDH = await computeDH(connState.keypair.sec, header.pub)
        const [next_root, recv_root] = await HKDF(connState.next_root, computedDH, 'ratchet-str')
        connState.prev_recv_root = connState.recv_root
        connState.prev_recv_cnt = connState.recv_cnt
        connState.next_root = next_root
        connState.recv_root = recv_root
        connState.curr_sender = false
        connState.recv_pub = header.pub
        recv_cnt = 0
      }
    } else if (connState.recv_pub != header.pub) {
      recv_cnt = connState.prev_recv_cnt
      if (header.send_cnt < recv_cnt) {
        const AES_key = connState.skipped[[header.pub, header.send_cnt]]
        delete connState.skipped[[header.pub, header.send_cnt]]
        const header_string = JSON.stringify(header)
        const plaintext = bufferToString(await decryptWithGCM(AES_key, ciphertext, header.receiverIV, header_string))
        return plaintext
      } else {
        const steps = header.send_cnt - recv_cnt
        for (let i = 0; i < steps; i++) {
          connState.skipped[[header.pub, recv_cnt + i]] = await HMACtoAESKey(connState.prev_recv_root, 'AES')
          connState.prev_recv_root = await HMACtoHMACKey(connState.prev_recv_root, 'HMAC')
        }

        const AES_key = await HMACtoAESKey(connState.prev_recv_root, 'AES')
        connState.prev_recv_root = await HMACtoHMACKey(connState.prev_recv_root, 'HMAC')
        connState.prev_recv_cnt = header.send_cnt + 1

        // decrypt

        const header_string = JSON.stringify(header)
        const plaintext = bufferToString(await decryptWithGCM(AES_key, ciphertext, header.receiverIV, header_string))

        return plaintext
      }
    }

    if (header.send_cnt < recv_cnt) {
      const AES_key = connState.skipped[[header.pub, header.send_cnt]]
      delete connState.skipped[[header.pub, header.send_cnt]]
      const header_string = JSON.stringify(header)
      const plaintext = bufferToString(await decryptWithGCM(AES_key, ciphertext, header.receiverIV, header_string))
      return plaintext
    }

    const steps = header.send_cnt - recv_cnt
    for (let i = 0; i < steps; i++) {
      connState.skipped[[header.pub, recv_cnt + i]] = await HMACtoAESKey(connState.recv_root, 'AES')
      connState.recv_root = await HMACtoHMACKey(connState.recv_root, 'HMAC')
    }

    const AES_key = await HMACtoAESKey(connState.recv_root, 'AES')
    connState.recv_root = await HMACtoHMACKey(connState.recv_root, 'HMAC')
    connState.recv_cnt = header.send_cnt + 1

    // decrypt

    const header_string = JSON.stringify(header)
    const plaintext = bufferToString(await decryptWithGCM(AES_key, ciphertext, header.receiverIV, header_string))

    return plaintext
  }
};

module.exports = {
  MessengerClient
}
