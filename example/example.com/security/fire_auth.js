'use strict'
const authPolicy = require('../security.json').accessControlsPolicy.authenticationPolicy
const MAX_LOGIN_ATTEMPTS = authPolicy.passwords.lockout.attempts
const LOCK_TIME = authPolicy.passwords.lockout.automaticReset
var failedAttempts = 0
let admin = require('firebase-admin')
const firebase = require('firebase')
require('firebase/auth')
require('firebase/database')
const secrets = require('./secrets')
let serviceAccount = require(secrets.fetchSecret('SERVICE_ACCOUNT'))

function checkSignIn () {
  let user = firebase.auth().currentUser
  if (user) {
    return user // returns true if there's a user signed in by that name
  } else {
    return false // returns false if there's no user signed in by that name
  }
}
async function lockout (email) {
  let toBeLocked = await admin.auth().getUserByEmail(email).then(record => { return record }).catch(err => { return err })
  await admin.auth().updateUser(toBeLocked.uid, { disabled: true }).then(ur => {
    // console.log(`User ${ur.displayName}'s account has been disabled`)
    return ur
  }).catch(err => { return err })
}
async function unlock (email) {
  let toBeUnlocked = await admin.auth().getUserByEmail(email).then(record => { return record })
  console.log(`I'm planning to unlock account ${toBeUnlocked.displayName} in ${LOCK_TIME} miliseconds`)
  setTimeout(async () => {
    await admin.auth().updateUser(toBeUnlocked.uid, { disabled: false }).catch(err => console.log(err))
    console.log(`User ${toBeUnlocked.displayName}'s account was previously disabled. It was unlocked at ${new Date().getDate()}`)
  }, LOCK_TIME)
}
async function register (uname, email, passwd) {
  if (email.length < 4) { // validate email
    let err = new Error('auth/invalid-email-address')
    err.status = 401
    return err
  }
  if (passwd.length < authPolicy.passwords.minLen) { // validate password
    let err = new Error('auth/password-too-short')
    err.status = 401
    return err
  }
  var passPolicy = new RegExp(authPolicy.passwords.regex, 'g')
  var res = passPolicy.test(passwd)
  if (res === false) {
    let err = new Error('auth/weak-password')
    err.status = 401
    return err
  }
  let newRecord = await admin.auth().createUser({
    displayName: uname,
    email: email,
    password: passwd,
    disabled: false
  }).catch(error => { return error })
  // BETA
  newRecord.sendEmailVerification().then(() => {
    console.log(`email verification for user ${newRecord.displayName} has been sent`)
  }).catch(err => {
    if (err) {
      return err
    }
  })
  if (!(newRecord instanceof Error)) {
    firebase.auth().signInWithEmailAndPassword(email, passwd).catch(error => console.log(error.code))
    return newRecord
  }
}
async function resetPassword (email) {
  await firebase.auth().sendPasswordResetEmail(email).then(function () {
    console.log(`user ${email} requested a password reset. An reset link was sent to this address at ${new Date().getDate()}`)
  }).catch(function (error) {
    if (error) {
      return error
    }
  })
}
async function changePassword (oldPassword, newPassword) {
  try {
    // first verify the current user's old password
    let user = firebase.auth().currentUser
    let cred = firebase.auth.EmailAuthProvider.credential(user.email, oldPassword)
    let updatedUser = await user.reauthenticateAndRetrieveDataWithCredential(cred)
    if (updatedUser !== undefined) {
      let message = await user.updatePassword(newPassword).then(() => {
        let msg = `User ${user.displayName}'s password was updated`
        return msg
      })
      console.log(message)
      return message
    }
  } catch (err) {
    return err
  }
}
module.exports = async (type, config, callback) => {
  if (type === 'firebase') {
    // initalize the app
    let firebaseConfig = {
      apiKey: secrets.fetchSecret('FIREBASE_API_KEY'),
      authDomain: secrets.fetchSecret('FIREBASE_AUTH_DOMAIN'),
      databaseURL: secrets.fetchSecret('FIREBASE_DB_URL'),
      projectId: secrets.fetchSecret('FIREBASE_PROJECT_ID'),
      storageBucket: secrets.fetchSecret('FIREBASE_STORAGE_BUCKET'),
      senderId: secrets.fetchSecret('FIREBASE_SENDER_ID')
    }
    !firebase.apps.length ? firebase.initializeApp(firebaseConfig) : firebase.app()
    !admin.apps.length ? admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
      databaseURL: secrets.fetchSecret('FIREBASE_DB_URL')
    }) : admin.app()
    // registration
    if (config.register) {
      let newUser = await register(config.register.username, config.register.email, config.register.password)
      if (newUser instanceof Error) {
        return newUser
      } else {
        let msg = `successfully created new user: ${newUser.displayName}`
        return {
          msg: msg,
          ur: newUser
        }
      }
    } else if (config.login) { // login
      let toBeLocked = await admin.auth().getUserByEmail(config.login.email).then(record => { return record })
      let loginSuccess = await firebase.auth().signInWithEmailAndPassword(config.login.email, config.login.password).then(record => {
        if (record.disabled === true) {
          admin.auth().updateUser(record.uid, { disabled: false })
          failedAttempts = 0
        }
        return record
      }).catch(error => {
        if (error.code === 'auth/wrong-password') {
          failedAttempts = failedAttempts + 1
          let remainingAttempts = MAX_LOGIN_ATTEMPTS - failedAttempts
          let err = new Error('auth/wrong-password')
          err.msg = `Login Failed. You have ${remainingAttempts} left`
          err.status = 401
          if (remainingAttempts === 0) {
            lockout(config.login.email)
            unlock(config.login.email)
          }
        } else if (error.code === 'auth/user-disabled') {
          // check to see if the account should be unlocked
          if (toBeLocked.disabled === true) {
            unlock(config.login.email)
            console.log(`It's too early to unlock the account ${toBeLocked.displayName}`)
            return error
          } else {
            unlock(config.login.email)
          }
        } else if (error.code === 'auth/too-many-requests') {
          lockout(config.login.email)
          console.log(`It looks like user ${toBeLocked.displayName} is up to some shenanigans. Account was locked as a precaution.`)
          unlock(config.login.email)
          return error
        }
        console.log(error.code)
        return error
      })
      return loginSuccess
    } else if (config.resetPassword) { // reset password
      await resetPassword(config.resetPassword.email).then(() => {
        return `Reset email sent to ${config.resetPassword.email}`
      }).catch(err => {
        return err
      })
    } else if (config.changePassword) {
      let changedUser = await changePassword(config.changePassword.old, config.changePassword.new).then(value => {
        return value
      }).catch(err => { return err })
      return changedUser
    } else if (config.logout) { // logout
      let user = checkSignIn()
      if (user) { // user is signed in, so sign them out
        let logoutSuccess = await firebase.auth().signOut().then(() => {
          let msg = `User ${user.displayName} has been signed out`
          return msg
        }).catch(err => {
          if (err) {
            return err
          }
        })
        return logoutSuccess
      }
      // else {
      //   let err = new Error(`No user to sign out`)
      //   err.status = 401
      //   return err
      // }
    }
  }
}
