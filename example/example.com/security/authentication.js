'use strict'
let firebase = require('firebase')
require('firebase/auth')
require('firebase/database')
// firebase environment variables
const FIREBASE_API_KEY =require('./secrets').fetchSecret('FIREBASE_API_KEY')
const FIREBASE_AUTH_DOMAIN = require('./secrets').fetchSecret('FIREBASE_AUTH_DOMAIN')
const FIREBASE_DB_URL = require('./secrets').fetchSecret('FIREBASE_DB_URL')
const FIREBASE_PROJECT_ID = require('./secrets').fetchSecret('FIREBASE_PROJECT_ID')
const FIREBASE_STORAGE_BUCKET = require('./secrets').fetchSecret('FIREBASE_STORAGE_BUCKET')
const FIREBASE_SENDER_ID = require('./secrets').fetchSecret('FIREBASE_SENDER_ID')
let mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const authPolicy = require('../security.json').accessControlsPolicy.authenticationPolicy
const MAX_LOGIN_ATTEMPTS = authPolicy.passwords.lockout.attempts
const LOCK_TIME = authPolicy.passwords.lockout.automaticReset
let schema = require('../schemas/userSchema').UserSchema
let name = 'User'

// Initialize Firebase
var config = {
  apiKey: FIREBASE_API_KEY,
  authDomain: FIREBASE_AUTH_DOMAIN,
  databaseURL: FIREBASE_DB_URL,
  projectId: FIREBASE_PROJECT_ID,
  storageBucket: FIREBASE_STORAGE_BUCKET,
  messagingSenderId: FIREBASE_SENDER_ID
}
firebase.initializeApp(config)
/* --------------------------------------- normal auth ---------------------------------------- */

schema.virtual('isLocked').get(function () {
  // check for a future lockUntil timestamp
  return !!(this.lockUntil && this.lockUntil > Date.now())
})
schema.pre('save', function (next) {
  var user = this
  // only hash the password if it has been modified (or is new)
  if (!user.isModified('password')) return next()

  // generate a salt
  const ROUNDS = require('./secrets').fetchSecret('HASH_ROUNDS') || 10
  bcrypt.genSalt(10, function (err, salt) {
    if (err) return next(err)

    bcrypt.hash(user.password, salt, function (err, hash) {
      if (err) return next(err)
      user.password = hash
      next()
    })
  })
})
schema.methods.comparePassword = function (candidatePassword, cb) {
  bcrypt.compare(candidatePassword, this.password, function (err, isMatch) {
    if (err) return cb(err)
    cb(null, isMatch)
  })
}
schema.methods.incLoginAttempts = function (cb) {
  // if we have a previous lock that has expired, restart at 1
  if (this.lockUntil && this.lockUntil < Date.now()) {
    return this.update({
      $set: { loginAttempts: 1 },
      $unset: { lockUntil: 1 }
    }, cb)
  }
  // otherwise we're incrementing
  var updates = { $inc: { loginAttempts: 1 } }
  // lock the account if we've reached max attempts and it's not locked already
  if (this.loginAttempts + 1 >= MAX_LOGIN_ATTEMPTS && !this.isLocked) {
    updates.$set = { lockUntil: Date.now() + LOCK_TIME }
  }
  return this.update(updates, cb)
}

let reasons = schema.statics = {
  failedLogin: {
    NOT_FOUND: 0,
    PASSWORD_INCORRECT: 1,
    MAX_ATTEMPTS: 2
  }
}
schema.statics.getAuthenticated = function (email, password, cb) {
  this.findOne({ email: email }, function (err, user) {
    if (err) return cb(err)

    // make sure the user exists
    if (!user) {
      return cb(null, null, reasons.NOT_FOUND)
    }
    // check if the account is currently locked
    if (user.isLocked) {
      // just increment login attempts if account is already locked
      return user.incLoginAttempts(function (err) {
        if (err) return cb(err)
        return cb(null, null, reasons.MAX_ATTEMPTS)
      })
    } // test for a matching password
    user.comparePassword(password, function (err, isMatch) {
      if (err) return cb(err)

      // check if the password was a match
      if (isMatch) {
        // if there's no lock or failed attempts, just return the user
        if (!user.loginAttempts && !user.lockUntil) return cb(null, user)
        // reset attempts and lock info
        var updates = {
          $set: { loginAttempts: 0 },
          $unset: { lockUntil: 1 }
        }
        return user.update(updates, function (err) {
          if (err) return cb(err)
          return cb(null, user)
        })
      }
      // password is incorrect, so increment login attempts before responding
      user.incLoginAttempts(function (err) {
        if (err) return cb(err)
        return cb(null, reasons.PASSWORD_INCORRECT)
      })
    })
  })
}

module.exports = {
  model: mongoose.model(name, schema),
  isAuthenticated: function (req, res, next) {
    var user = firebase.auth().currentUser
    if (user !== null) {
      req.user = user
      next()
    } else {
      res.redirect('/login')
    }
  }
}
