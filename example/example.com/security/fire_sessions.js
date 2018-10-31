let admin = require('firebase-admin')
const firebase = require('firebase')
require('firebase/auth')
require('firebase/database')
const secrets = require('./secrets')
let serviceAccount = require(secrets.fetchSecret('SERVICE_ACCOUNT'))
let fireAuth = require('./fire_auth')

module.exports = async (request, response, callback) => {
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

  firebase.auth().setPersistence(firebase.auth.Auth.Persistence.NONE)
  // sign in a user
  let token = fireAuth('firebase', { login: { email: request.body.email, password: request.body.password } }).then(userRecord => {
    return userRecord.getToken()
  }).catch(err => { return err })
  // firebase create cookies
  // firebase csrf protections

}
