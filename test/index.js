
import { isSupported, getInfo, getRandom, initWallet, wipeoutWallet, verifyPin, getPublicKey, signData } from '../src/index.js'

function fillU2fStatus () {
  isSupported().then((result) => {
    var elem = document.getElementById('u2fStatus')
    elem.innerHTML = 'U2F support: ' + result
  })
    .catch((err) => {
      setStatusBarText(err)
    })
}

function fillWalletInfo () {
  var text = ''

  getInfo(30).then((info) => {
    text = 'Wallet info:<br/>' +
      'App version: ' + info.version + '<br/>'

    if (info.walletInitialized === true) {
      text += 'Wallet status: initialized<br/>'
    } else {
      text += 'Wallet status: not initialized<br/>'
    }

    if (info.pinVerified === true) {
      text += 'Pin status: verified<br/>'
    } else {
      text += 'Pin status: unverified<br/>'
    }

    var elem = document.getElementById('walletInfo')
    elem.innerHTML = text
  })
    .catch((err) => {
      setStatusBarText(err)
    })
}

function onClickGetRandom () {
  getRandom(30, 16).then((random) => {
    var elem = document.getElementById('getRandomInput')
    elem.value = random.toString('hex')

    setStatusBarText('Done')
  })
    .catch((err) => {
      setStatusBarText(err)
    })
}

function OnClickInitWallet () {
  var secretKeyElem = document.getElementById('initWalletSecretKeyInput')
  var pinElem = document.getElementById('initWalletPinInput')

  initWallet(30, 'xrpSecret', secretKeyElem.value, pinElem.value).then(() => {
    setStatusBarText('Done')
  })
    .catch((err) => {
      setStatusBarText(err)
    })
}

function OnClickWipeoutWallet () {
  wipeoutWallet(30).then(() => {
    setStatusBarText('Done')
  })
    .catch((err) => {
      setStatusBarText(err)
    })
}

function OnClickVerifyPin () {
  var elem = document.getElementById('verifyPinInput')

  verifyPin(30, elem.value).then(() => {
    setStatusBarText('Done')
  })
    .catch((err) => {
      setStatusBarText(err)
    })
}

function onClickGetPublicKey () {
  getPublicKey(30).then((publicKey) => {
    var elem = document.getElementById('getPublicKeyInput')
    elem.value = publicKey.toString('hex')

    setStatusBarText('Done')
  })
    .catch((err) => {
      setStatusBarText(err)
    })
}

function OnClickSignData () {
  var elem = document.getElementById('signDataDataToSignInput')

  signData(70, elem.value).then((signature) => {
    var elem = document.getElementById('signDataSignatureInput')
    elem.value = signature.toString('hex')

    setStatusBarText('Done')
  })
    .catch((err) => {
      setStatusBarText(err)
    })
}

function setStatusBarText (text) {
  var elem = document.getElementById('statusBar')
  elem.innerHTML = text
}

document.addEventListener('DOMContentLoaded', function (event) {
  document.getElementById('getRandomButton').onclick = onClickGetRandom
  document.getElementById('initWalletButton').onclick = OnClickInitWallet
  document.getElementById('wipeoutWalletButton').onclick = OnClickWipeoutWallet
  document.getElementById('verifyPinButton').onclick = OnClickVerifyPin
  document.getElementById('getPublicKeyButton').onclick = onClickGetPublicKey
  document.getElementById('signDataButton').onclick = OnClickSignData

  fillU2fStatus()
  fillWalletInfo()
})
