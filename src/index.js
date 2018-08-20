
/**
 * @file Javascript API for the Secalot XRP wallet.<br><br>
 * The secalot XRP wallet is designed to securely store cryptographic keys corresponding to user's XRP account and to sign XRP transactions.
 * To sign a transaction, the transaction data is transferred to the device, hashed there and signed. The signature is returned back from the device.<br><br>
 * Commands and responses between the wallet and the host software can be exchanged via Secalot's CCID smart card interface and via Secalot's U2F interface
 * via a so called U2F tunneling.
 * The first is designed to be used by desktop applications and the second is to be used by websites utilizing browser's U2F support.
 * This api is using the U2F transport.<br><br>
 * The wallet can be in two states, initialized and wiped. In the wiped state most of wallet's functionality is not available.<br>
 * The wallet holds one 256 bit ECDSA private key that has to be loaded when the wallet is initialized. The wallet provides a source of random numbers that can be used
 * to generate the key. In any case the key always comes from the host side so that it can be displayed to the user before being written to the wallet.<br>
 * Some of wallet's functionality is protected by a PIN-code that has to be set during wallet's initialization. The PIN-code should be between 4 and 32 bytes long.
 * After wrong PIN-code is presented to a wallet three times in a row, the wallet is permanently wiped and has to be initialized again.
 * @author Matvey Mukha
 * @module secalot-xrp-api
 */

import { isSupported, sign } from 'u2f-api'

function webSafe64 (base64) {
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function normal64 (base64) {
  return base64.replace(/\-/g, '+').replace(/_/g, '/') + '=='.substring(0, (3 * base64.length) % 4)
}

function sendAPDU (apdu, timeout) {
  return new Promise(function (resolve, reject) {
    var xrpMagic = Buffer.from('8877665544332211', 'hex')
    var challenge = Buffer.from('0000000000000000000000000000000000000000000000000000000000000000', 'hex')

    var keyHandle = Buffer.concat([xrpMagic, apdu])

    var signRequest = {
      version: 'U2F_V2',
      challenge: webSafe64(challenge.toString('base64')),
      keyHandle: webSafe64(keyHandle.toString('base64')),
      appId: location.origin
    }

    sign([signRequest], timeout).then((response) => {
      if (typeof response['signatureData'] !== 'undefined') {
        var data = Buffer.from((normal64(response['signatureData'])), 'base64')

        if (data.length < 2) {
          reject(new Error('Invalid response APDU.'))
          return
        }

        resolve(data)
      } else {
        reject(new Error('Failed to send an APDU.'))
      }
    })
      .catch((err) => {
        reject(err)
      })
  })
}

/**
 * @typedef {Object} XRPInfo
 * @property {string} version Secalot XRP wallet version
 * @property {boolean} walletInitialized Is the wallet initialized
 * @property {boolean} pinVerified Is the PIN-code verified
 */

/**
 * Get info about the Secalot XRP wallet.
 *
 * @param {number} timeout Timeout in seconds
 * @returns {XRPInfo} Secalot XRP wallet info
 */
function getInfo (timeout) {
  return new Promise(function (resolve, reject) {
    var apdu = Buffer.from('80C40000', 'hex')

    sendAPDU(apdu, timeout).then((response) => {
      if ((response[response.length - 2] !== 0x90) || (response[response.length - 1] !== 0x00)) {
        reject(new Error('Invalid APDU response.'))
        return
      }

      if (response.length !== 10) {
        reject(new Error('Invalid APDU response.'))
        return
      }

      var info = {
        version: response[0].toString() + '.' + response[1].toString(),
        walletInitialized: (response[2] & 0x01) === 0x01,
        pinVerified: (response[2] & 0x02) === 0x02
      }

      resolve(info)
    })
      .catch((err) => {
        reject(err)
      })
  })
}

/**
 * Get random data
 *
 * @param {number} timeout Timeout in seconds
 * @param {number} length Length of the requested random data. From 1 to 128 bytes.
 * @returns {Buffer} Random data
 */
function getRandom (timeout, length) {
  return new Promise(function (resolve, reject) {
    if ((length === 0) || (length > 128)) {
      reject(new Error('Invalid length.'))
      return
    }

    var apdu = Buffer.from('80C0000000', 'hex')

    apdu[4] = length

    sendAPDU(apdu, timeout).then((response) => {
      if ((response[response.length - 2] !== 0x90) || (response[response.length - 1] !== 0x00)) {
        reject(new Error('Invalid APDU response.'))
        return
      }

      if (response.length !== (length + 2)) {
        reject(new Error('Invalid APDU response.'))
        return
      }

      response = response.slice(0, (response.length - 2))

      resolve(response)
    })
      .catch((err) => {
        reject(err)
      })
  })
}

/**
 * Initialize the wallet.
 * Wallet has to be in a wiped state.
 *
 * @param {number} timeout Timeout in seconds
 * @param {string} privateKey The private key. 32 bytes as a hex string.
 * @param {string} pin A new PIN-code. Between 4 and 32 bytes.
 */
function initWallet (timeout, privateKey, pin) {
  return new Promise(function (resolve, reject) {
    privateKey = Buffer.from(privateKey, 'hex')
    pin = Buffer.from(pin, 'utf8')

    if (privateKey.length !== 32) {
      reject(new Error('Invalid private key length.'))
      return
    }

    if ((pin.length < 4) || (pin.length > 32)) {
      reject(new Error('Invalid pin length.'))
      return
    }

    var apdu = Buffer.alloc(5 + 1 + privateKey.length + pin.length)

    apdu[0] = 0x80
    apdu[1] = 0x20
    apdu[2] = 0x00
    apdu[3] = 0x00
    apdu[4] = 1 + pin.length + privateKey.length

    apdu[5] = pin.length

    pin.copy(apdu, 6, 0, pin.length)
    privateKey.copy(apdu, 6 + pin.length, 0, privateKey.length)

    sendAPDU(apdu, timeout).then((response) => {
      if (response.length !== 2) {
        reject(new Error('Invalid APDU response.'))
        return
      }

      if ((response[0] !== 0x90) || (response[1] !== 0x00)) {
        if ((response[0] === 0x6d) && (response[1] === 0x00)) {
          reject(new Error('Wallet already initialized.'))
          return
        } else {
          reject(new Error('Invalid APDU response.'))
          return
        }
      }

      resolve()
    })
      .catch((err) => {
        reject(err)
      })
  })
}

/**
 * Wipe out the wallet.
 * The wallet has to be in an initialized state.
 *
 * @param {number} timeout Timeout in seconds
 */
function wipeoutWallet (timeout) {
  return new Promise(function (resolve, reject) {
    var apdu = Buffer.from('80F0000000', 'hex')

    sendAPDU(apdu, timeout).then((response) => {
      if (response.length !== 2) {
        reject(new Error('Invalid APDU response.'))
        return
      }

      if ((response[0] !== 0x90) || (response[1] !== 0x00)) {
        if ((response[0] === 0x6d) && (response[1] === 0x00)) {
          reject(new Error('Wallet not initialized.'))
          return
        } else {
          reject(new Error('Invalid APDU response.'))
          return
        }
      }

      resolve()
    })
      .catch((err) => {
        reject(err)
      })
  })
}

/**
 * Verify a PIN-code.
 * The wallet has to be initialized.
 * After the third unsuccessful verification the wallet is permanently wiped out.
 *
 * @param {number} timeout Timeout in seconds
 * @param {string} pin PIN-code to verify. Between 4 and 32 bytes.
 */
function verifyPin (timeout, pin) {
  return new Promise(function (resolve, reject) {
    pin = Buffer.from(pin, 'utf8')

    if ((pin.length < 4) || (pin.length > 32)) {
      reject(new Error('Invalid pin length.'))
      return
    }

    var apdu = Buffer.alloc(5 + pin.length)

    apdu[0] = 0x80
    apdu[1] = 0x22
    apdu[2] = 0x00
    apdu[3] = 0x00
    apdu[4] = pin.length

    pin.copy(apdu, 5, 0, pin.length)

    sendAPDU(apdu, timeout).then((response) => {
      if (response.length !== 2) {
        reject(new Error('Invalid APDU response.'))
        return
      }

      if ((response[0] !== 0x90) || (response[1] !== 0x00)) {
        if ((response[0] === 0x6d) && (response[1] === 0x00)) {
          reject(new Error('Wallet not initialized.'))
          return
        } else if ((response[0] === 0x69) && (response[1] === 0x82)) {
          getPinTriesLeft(timeout).then((triesLeft) => {
            reject(new Error('Invalid PIN-code. ' + triesLeft.toString() + ' tries left.'))
          })
            .catch((err) => {
              reject(err)
            })

          return
        } else if ((response[0] === 0x67) && (response[1] === 0x00)) {
          reject(new Error('Unsupported PIN-code length.'))
          return
        } else if ((response[0] === 0x69) && (response[1] === 0x83)) {
          reject(new Error('PIN-code blocked.'))
          return
        } else {
          reject(new Error('Invalid APDU response.'))
          return
        }
      }

      resolve()
    })
      .catch((err) => {
        reject(err)
      })
  })
}

function getPinTriesLeft (timeout) {
  return new Promise(function (resolve, reject) {
    var apdu = Buffer.from('80228000', 'hex')

    sendAPDU(apdu, timeout).then((response) => {
      if (response.length !== 2) {
        reject(new Error('Invalid APDU response.'))
        return
      }

      if (response[0] !== 0x63) {
        if ((response[0] === 0x6d) && (response[1] === 0x00)) {
          reject(new Error('Wallet not initialized.'))
          return
        } else {
          reject(new Error('Invalid APDU response.'))
          return
        }
      }

      resolve(response[1] - 0xC0)
    })
      .catch((err) => {
        reject(err)
      })
  })
}

/**
 * Get the wallet's public key.
 * The wallet has to be initialized and a PIN-code has to ve verified.
 *
 * @param {number} timeout Timeout in seconds
 * @returns {Buffer} The public key
 */
function getPublicKey (timeout) {
  return new Promise(function (resolve, reject) {
    var apdu = Buffer.from('80400000', 'hex')

    sendAPDU(apdu, timeout).then((response) => {
      if ((response[response.length - 2] !== 0x90) || (response[response.length - 1] !== 0x00)) {
        if ((response[response.length - 2] === 0x6d) && (response[response.length - 1] === 0x00)) {
          reject(new Error('Wallet not initialized.'))
          return
        } else if ((response[response.length - 2] === 0x69) && (response[response.length - 1] === 0x82)) {
          reject(new Error('PIN-code not verified.'))
          return
        } else {
          reject(new Error('Invalid APDU response.'))
          return
        }
      }

      if (response.length !== 67) {
        reject(new Error('Invalid APDU response.'))
        return
      }

      response = response.slice(0, (response.length - 2))

      resolve(response)
    })
      .catch((err) => {
        reject(err)
      })
  })
}

/**
 * Sign a transaction.
 * The wallet has to be initialized and a PIN-code has to ve verified.
 *
 * @param {number} timeout Timeout in seconds
 * @param {string} dataToSign Transaction data to sign. As a hex string.
 * @returns {Buffer} Signature
 */
function signData (timeout, dataToSign) {
  return new Promise(function (resolve, reject) {
    var offset = 0
    var rawData
    var apdus = []

    rawData = Buffer.from(dataToSign, 'hex')

    while (offset !== rawData.length) {
      var maxChunkSize = 8
      var chunkSize = (offset + maxChunkSize > rawData.length ? rawData.length - offset : maxChunkSize)
      var apdu = Buffer.alloc(5 + chunkSize)
      apdu[0] = 0x80
      apdu[1] = 0xF2
      apdu[2] = (offset === 0 ? 0x00 : 0x01)
      apdu[3] = 0x00
      apdu[4] = chunkSize

      rawData.copy(apdu, 5, offset, offset + chunkSize)
      apdus.push(apdu)
      offset += chunkSize
    }

    var localCallback = function () {
      sendAPDU(apdus.shift(), timeout).then((response) => {
        if (response.length !== 2) {
          reject(new Error('Invalid APDU response.'))
          return
        }

        if ((response[0] !== 0x90) || (response[1] !== 0x00)) {
          if ((response[0] === 0x6d) && (response[1] === 0x00)) {
            reject(new Error('Wallet not initialized.'))
            return
          } else if ((response[0] === 0x69) && (response[1] === 0x82)) {
            reject(new Error('PIN-code not verified.'))
            return
          } else {
            reject(new Error('Invalid APDU response.'))
            return
          }
        }

        if (apdus.length === 0) {
          var apdu = Buffer.from('80f20200', 'hex')

          sendAPDU(apdu, timeout).then((response) => {
            if ((response[response.length - 2] !== 0x90) || (response[response.length - 1] !== 0x00)) {
              reject(new Error('Invalid APDU response.'))
              return
            }

            response = response.slice(0, (response.length - 2))

            resolve(response)
          })
            .catch((err) => {
              reject(err)
            })
        } else {
          localCallback()
        }
      })
        .catch((err) => {
          reject(err)
        })
    }

    localCallback()
  })
}

export { isSupported, getInfo, getRandom, initWallet, wipeoutWallet, verifyPin, getPublicKey, signData }
