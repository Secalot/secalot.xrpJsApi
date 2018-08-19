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

