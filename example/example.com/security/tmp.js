'use strict'
const bcrypt = require('bcrypt')
const database = require('./database')
const authPolicy = require('../security.json').accessControlsPolicy.authenticationPolicy
const timeout = authPolicy.passwords.lockout.tarpitDefault
const MAX_LOGIN_ATTEMPTS = authPolicy.passwords.lockout.attempts
const LOCK_TIME = authPolicy.passwords.lockout.automaticReset
let reasons =
    UserSchema.statics.failedLogin = {
        NOT_FOUND: 0,
        PASSWORD_INCORRECT: 1,
        MAX_ATTEMPTS: 2
    }
// const rbac = require('rbac')

// All functions, modules and exports here are related to providing secure ACCESS to the application
const tarpit = (response) => {
    setTimeout(() => {
        response()
    }, timeout)
}

/* ------------------------------- authentication ------------------------------------------- */
// REGISTRATION/ENROLLMENT
function addRecord(model, data, callback) {
    database().createRecord(model, data, function (err, record) {
        if (err) {
            return callback(err)
        } else {
            return callback(null, record)
        }
    })
}
// LOGIN
function locked(schema) {
    schema.virtual('isLocked').get(function () {
        // check for a future lockUntil timestamp
        return !!(this.lockUntil && this.lockUntil > Date.now());
    })
}

function authSetup(schema, model) {
    let schemaObject = schema.statics
    schemaObject.authenticate = function (email, password, callback) {
        model.findOne({ email: email }).exec(function (error, user) {
            if (error) return callback(error)
            else if (!user) {
                let err = new Error(`User ${user} not found`)
                err.status = 401
                return callback(err, reasons.NOT_FOUND)
            }
            // check if the account is currently locked
            if (user.isLocked) {
                // just increment login attempts if account is already locked
                return user.incLoginAttempts(function (err) {
                    if (err) return callback(err)
                    return callback(null, reasons.MAX_ATTEMPTS)
                })
            } else {
                bcrypt.compare(password, user.password, function (err, data) {
                    if (data === true) {
                        return callback(null, user)
                    } else return callback(err)
                })
            }
        })
    }
    return schema.statics.authenticate
}
function lockOut(schema) {
    schema.methods = {
        incLoginAttempts: function (cb) {
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
                updates.$set = { lockUntil: Date.now() + LOCK_TIME };
            }
            return this.update(updates, cb);
        }
    }
}

// REMEMBER ME
// LOGOUT
// PASSWORDS
// INITIAL STORAGE
let hashPassword = function (data) {
    return bcrypt.hashSync(data.password, 10)
}
// FORGOT PASSWORD => MAGIC LINK???
// CHANGE PASSWORD
// ACCOUNT LOCKOUT
/* -------------------------------- authorization ------------------------------------------- */
// DANGEROUS REDIRECTS
// ROLE BASED ACCESS CONTROL
module.exports = {
    addRecord: addRecord,
    authSetup: authSetup,
    hashPassword: hashPassword,
    tarpit: tarpit
}
