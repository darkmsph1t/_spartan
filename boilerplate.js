'use strict'
var chalk = require('chalk')
var { spawn } = require('child_process')
var fs = require('fs')
var path = require('path')
var pathToBoilerPlate = path.resolve('./security.js')
let modules = []
// should add in a function to validate security.json before writing boilerplate
function validatePolicy () {

}
function matches (allPkgs, currentPkgs) {
  // get packages from package.json
  // var temp = Object.keys(pkgJson.dependencies);
  return currentPkgs.filter(x => allPkgs.includes(x))
}
function diff (old, current) {
  try {
    return old.filter(x => !current.includes(x))
  } catch (e) {
    console.log(e)
  }
}
function removeModules (modules) {
  var remove = spawn('npm', ['uninstall', modules])
}

function installModules (modules) {
  var install = spawn('npm'['install', '--save', modules])
}

function appDepBp (p) {
  try {
    modules.push('gulp')
    modules.push('synk')
    let code =  `'use strict'
    let gulp = require('gulp')
    let { spawn } = require('child_process')
    /* this module is designed and written to identify vulnerabilities associated with application dependencies. The most opportune time to discover these vulnerabilities is PRIOR to application deployment (e.g. as part of your CI/CD pipeline) as such, this module utilizes \`synk\` for this purpose (with the \`synk test\` command ideally included early in the package.json test parameter). Assuming you have already installed the synk module and signed up for an account, the following tasks can be included in your gulpfile OR run as a separate gulpfile by using \`gulp --gulpfile <path to this file>\` at the command line
    */

    gulp.task('synk_auth', function (err, end) {
      if (err) return err
      spawn('snyk', ['auth'])
      end()
    })
    gulp.task('snyk_test', function (err, done) {
      if (err) return err
      spawn('synk', ['test'])
      done()
    })
    gulp.task('snyk_wizard', function (err, complete) {
      if (err) return err
      spawn('synk', ['wizard'])
      complete()
    })
    gulp.task('default', gulp.series(('synk_auth', 'synk_test', 'snyk_wizard'), function (err, done) {
      if (err) return err
      console.log('Application Dependency Check Complete!')
      done()
    }))`
    return {
      code: code,
      modules: modules
    }
  } catch (e) {
    console.log('Could not write application dependencies file')
  }
}
function apiBp(p) {
  try {
    modules.push('express-rate-limiter')
    let code2 = `'use strict'

/* The purpose of this module is to ensure that APIs are designed, built, maintained and sustained. This is done by achieving the following objectives:
  1. Ensure that all endpoints are provided over a secure connection (HTTPS)
  2. Utilization of access control mechanisms where appropriate for non-public APIs
  3. Issuance and validation of JWTs for intra-service authentication
  4. Issuance and validation of API Keys for external users and inter-service communication
  5. Dynamic rate limiting => by endpoint && by time
  6. Validation of input, parameters and content types
*/

module.exports = function apiSec () {
  function secureConnection () {

  }
  function apiAccessControl () {

  }
  function getJwt () {

  }
  function issueJwt () {

  }
  function getApiKey () {

  }
  function issueApiKey () {

  }
  function rateLimiter () {

  }
  function validator () {

  }
}`
return {
  code: code2,
  modules: modules
}
  } catch (e) {
    console.log('Could not write api security file')
  }
}
function accessCtrlBp(p) {
  try {
    modules.push('mongoose')
    modules.push('bcrypt')
    let code = `'use strict'
let mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const authPolicy = require('../security.json').accessControlsPolicy.authenticationPolicy
const MAX_LOGIN_ATTEMPTS = authPolicy.passwords.lockout.attempts
const LOCK_TIME = authPolicy.passwords.lockout.automaticReset
let schema = require('../schemas/userSchema').UserSchema // <--- expects that you have built a user schema
let name = 'User'

/* --------------------------------------- local auth ---------------------------------------- */

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
  model: mongoose.model(name, schema)
}`
    return {
      modules: modules,
      code: code
    }
  } 
 catch (e) {
    console.log('Could not write access control file')
  }
}
function firebaseBp() {
  try {
    modules.push('firebase-admin')
    modules.push('firebase')
    let code = `'use strict'
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
    // console.log(\`User \${ ur.displayName } 's account has been disabled\`)
    return ur
  }).catch (err => { return err })
}
async function unlock(email) {
  let toBeUnlocked = await admin.auth().getUserByEmail(email).then(record => { return record })
  console.log(\`I'm planning to unlock account \${toBeUnlocked.displayName} in \${LOCK_TIME} miliseconds\`)
  setTimeout(async () => {
    await admin.auth().updateUser(toBeUnlocked.uid, { disabled: false }).catch(err => console.log(err))
    console.log(\`User \${toBeUnlocked.displayName}'s account was previously disabled. It was unlocked at \${new Date().getDate()}\`)
  }, LOCK_TIME)
}
async function register(uname, email, passwd) {
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
  if (!(newRecord instanceof Error)) {
    firebase.auth().signInWithEmailAndPassword(email, passwd).catch(error => console.log(error.code))
    return newRecord
  }
}
async function resetPassword(email) {
  await firebase.auth().sendPasswordResetEmail(email).then(function () {
    console.log(\`user \${email} requested a password reset. An reset link was sent to this address at \${new Date().getDate()}\`)
  }).catch(function (error) {
    if (error) {
      return error
    }
  })
}
async function changePassword(oldPassword, newPassword) {
  try {
    // first verify the current user's old password
    let user = firebase.auth().currentUser
    let cred = firebase.auth.EmailAuthProvider.credential(user.email, oldPassword)
    let updatedUser = await user.reauthenticateAndRetrieveDataWithCredential(cred)
    if (updatedUser !== undefined) {
      let message = await user.updatePassword(newPassword).then(() => {
        let msg = \`User \${user.displayName}'s password was updated\`
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
        let msg = \`successfully created new user: \${newUser.displayName}\`
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
          err.msg = \`Login Failed. You have \${remainingAttempts} left\`
          err.status = 401
          if (remainingAttempts === 0) {
            lockout(config.login.email)
            unlock(config.login.email)
          }
        } else if (error.code === 'auth/user-disabled') {
          // check to see if the account should be unlocked
          if (toBeLocked.disabled === true) {
            unlock(config.login.email)
            console.log(\`It's too early to unlock the account \${toBeLocked.displayName}\`)
            return error
          } else {
            unlock(config.login.email)
          }
        } else if (error.code === 'auth/too-many-requests') {
          lockout(config.login.email)
          console.log(\`It looks like user \${toBeLocked.displayName} is up to some shenanigans. Account was locked as a precaution.\`)
          unlock(config.login.email)
          return error
        }
        console.log(error.code)
        return error
      })
      return loginSuccess
    } else if (config.resetPassword) { // reset password
      await resetPassword(config.resetPassword.email).then(() => {
        return \`Reset email sent to \${config.resetPassword.email}\`
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
          let msg = \`User \${user.displayName} has been signed out\`
          return msg
        }).catch(err => {
          if (err) {
            return err
          }
        })
        return logoutSuccess
      }
      // else {
      //   let err = new Error(\`No user to sign out\`)
      //   err.status = 401
      //   return err
      // }
    }
  }
}`
    return {
      modules: modules,
      code: code
    }
  } catch (e) {
    console.log('Could  not write firebase boilerplate')
  }
}
function secretBp(p) {
  try {
    modules.push('dotenv')
    let code = `'use strict'
require('dotenv').config()
/* Pretty much, the only purpose of this file is to safely load environment variables.
   By default, will only load if the environment HAS NOT been identified as production (e.g. stage, dev, uat). To use this, module effectively, run \`npm install dotenv--save\` and create a .env file.
   BE SURE TO ADD THE .ENV FILE TO YOUR .GITIGNORE FILE
*/
function fetchSecret (variable) {
  if (process.env.NODE_ENV !== 'production') {
    require('dotenv').load()
    return process.env[variable]
  } else {
    let error = new Error(\`Could not fetch variable \${ variable }.It is not available in this environment\`)
    return error
  }
}

module.exports.fetchSecret = fetchSecret`
  return {
    modules: modules,
    code: code
  }
  } catch (e) {
    console.log('Could not write secrets management file')
  }
}
function formBp (p) {
  try {
    let code = `'use strict'
const secJson = require('../security.json')

module.exports = function formSec (request, response, callback) {
  if (secJson.formProtection.enabled !== true) {
    let error = new Error('Form protection disabled by policy')
    error.status = 400
    return callback(error)
  } else if (secJson.formProtection.config.methodOverride === false && (request.method !== 'GET' || request.method !== 'POST')) {
    let error = new Error('Method override disabled by policy')
    error.status = 400
    return callback(error)
  } else {
    let autocomplete = 'off'
    if (secJson.formProtection.config.autocompleteAllowed === true) {
      autocomplete = 'on'
    }
    let test = request.csrfToken()
    console.log(test)
    return {
      autocomplete: autocomplete,
      method: request.method,
      _csrf: test
    }
  }
}`
  return {
    code: code
  }
} catch (e) {
    console.log('Could not write forms protection file')
  }
}
function sessionBp (p) {
  try {
    modules.push('express-session')
    modules.push('redis')
    modules.push('connect-redis')
    let code = `'use strict'
const secJson = require('../security.json').sessionPolicy
const secrets = require('./secrets')
const session = require('express-session')
let redis = require('redis').createClient()
let RedisStore = require('connect-redis')(session)
let redisOptions = {
  host: secJson.hostname,
  port: secrets.fetchSecret('REDIS_PORT'),
  client: redis,
  ttl: secJson.config.duration.ttl
}
let obj = {
  secret: secrets.fetchSecret('SESSION_SECRET'),
  // rolling: true,
  // resave: true,
  saveUninitialized: false,
  cookie: {
    path: secJson.config.path,
    httpOnly: secJson.config.cookies.httpOnly,
    secure: true,
    maxAge: secJson.config.duration.ttl * 1000
  },
  store: new RedisStore(redisOptions),
  // store: new MongoStore({
  //   mongooseConnection: security.database,
  //   ttl: (secJson.config.duration.ttl)
  // }),
  name: 'spartan'
}

/* This module is concerned with the set up, tear down and protection of sessions
   Obligations:
   1. Prevention of session hijacking
      a. Generation of session ids, cookies
      b. Creation, verification of session ids tied to a session store
      c. Regenerating session ids (reauthentication) on priviledged access areas
      d. Destruction of session ids after a set period of time (ttl, idle time expiration, cookie expiration), manual logout or moving to a privileged access area
   2. Providing a means to generate new cookies which are secure (httpOnly, secure, same-site)
   3. Prevention of cross-site-reguest forgery
*/

/* ---------------------------------------- set-up ---------------------------------------------- */
function sessioner (next) {
  // session.Session.prototype.login = function (user, callback) {
  //   const request = this.request
  //   request.session.regenerate(function (err) {
  //     if (err) {
  //       callback(err)
  //     }
  //   })
  // }
  if (secJson.enabled === true) {
    if (secJson.config.duration.idle) { // destroys the session after a period of idle time
      obj.resave = true
      obj.rolling = true
      obj.cookie = { maxAge: secJson.config.duration.idle }
    }
    if (secJson.config.cookies.sameSite) {
      obj.cookie = { sameSite: secJson.config.cookies.sameSite }
    }
    if (secJson.config.cookies.domain === null && secJson.config.cookies.path === '/' && secJson.config.cookies.secure === true) {
      obj.name = \`\${ secJson.config.cookies.prefixes[0] } -\${ secJson.config.cookies.name } \`
    } else if (secJson.config.cookies.secure === true) {
      obj.name = \`\${ secJson.config.cookies.prefixes[1] } -\${ secJson.config.cookies.name } \`
    }
    return session(obj)
  } else {
    let err = new Error('Session Management disabled by policy')
    err.status = 500
    next(err)
  }
}
/* ---------------------------------------- cookies --------------------------------------------- */
const cookieMonster = function (response, options, callback) {
  response.clearCookie(options.name, options.options, function (err) {
    if (err) {
      return callback(err)
    }
  }) // destroys the session cookie
}
const cookieMaker = function (request, response, options, callback) {
  // if required parameters are missing, error
  if (!options.name || !options.value) {
    let error = new Error('Required parameters missing')
    return callback(error)
  }
  // returns a new secure cookie if there's a secure server/connection
  if (request.secure === true) {
    options.options = { httpOnly: true }
    options.options = { secure: true }
    if (!options.options.domain && options.options.path === '/') {
      options.name = \`_Host - \${ options.name }\`
    }
    return callback(null, response.cookie(options.name, options.value, options.options))
  } else {
    let error = new Error('No secure cookies for you! insecure connection detected')
    return callback(error)
  }
}

module.exports.sessioner = sessioner
module.exports.cookieMonster = cookieMonster
module.exports.cookieMaker = cookieMaker
`
return {
  code: code,
  modules: modules
}
  } catch (e) {
    console.log('Could not write session management file')
  }
}
function headersBp (p) {
  try {
    modules.push('helmet')
    modules.push('uuidv4')
    let code = `'use strict'
const secJson = require('../security.json')
// const valid = require('./validation')
const helmet = require('helmet')
const uuidv4 = require('uuid/v4')

const makeNonceExpress = function (request, response, next) {
  response.locals.nonce = uuidv4
  next()
}
const makeNonce = function (thingToNonce) {
  thingToNonce.nonce = uuidv4
  return thingToNonce.nonce
}
const makeHashExpress = function (request, response, next) {
  // response.locals.hash = hasher(response.body)
  next()
}
const makeHash = function (object) {
  try {
    let hashedSites = {}
    for (let keys in object.directives) {
      for (let site = 0; site < keys.length; site++) {
      // hashedSites[keys] = { [keys]: \`sha256 - \${ hasher(keys[site]) } \` }
      }
    }
    console.log(hashedSites)
  } catch (e) {
    console.log(e)
  }
}
function setHeaders (options) {
  // if (valid(secJson.securityHeaders.config.csp)) {
  //  const headers = secJson.securityHeaders.config.csp
  // }
  if (!options) {
    return helmet()
  }
  let headers = {}
  for (let keys = 0; keys < Object.keys(options).length; keys++) {
    if (options.csp) {
      const csp = secJson.securityHeaders.config.csp
      let d = csp.directives
      // try { makeHash(csp) } catch (e) { console.log(e) }
      d['blockAllMixedContent'] = csp.blockAllMixedContent
      if (!csp.reportOnly) {
        let sri = []
        if (csp.requireSriFor.scripts) {
          sri.push('script')
        }
        if (csp.requireSriFor.styles) {
          sri.push('style')
        }
        d['requireSriFor'] = sri
      }
      if (csp.sandbox.enable) {
        let sandbox = []
        for (let l in csp.sandbox) {
          if (csp.sandbox[l]) {
            sandbox.push(l)
          }
        }
        sandbox.splice(0, 1)
        d['sandbox'] = sandbox
      }
      d['upgradeInsecureRequests'] = csp.upgradeInsecureRequests
      d['reportUri'] = csp.reportUri.uriLocation
      headers.contentSecurityPolicy = {
        directives: d,
        reportOnly: csp.reportOnly,
        setAllHeaders: false
      }
    } else {
      headers.contentSecurityPolicy = false
    }
    if (options.cdp) {
      headers.permittedCrossDomainPolicies = { permittedPolicies: 'none' }
    }
    if (options.preFetch === false) {
      headers.dnsPrefetchControl = false
    } else {
      headers.dnsPrefetchControl = { allow: true }
    }
    if (options.noClickJack === false) {
      headers.frameguard = false
    } else if (options.noClickJack && secJson.securityHeaders.config.preventClickJacking) {
      headers.frameguard = { action: 'deny' }
    } else {
      // do nothing
    }
    if (options.hidePower === false) {
      headers.hidePoweredBy = false
    } else if (options.hidePower.setTo && typeof options.hidePower.setTo === 'string') {
      headers.hidePoweredBy = { setTo: options.hidePower.setTo }
    } else {
      // do nothing
    }
    if (options.ect) {
      headers.expectCt = {
        enforce: true,
        maxAge: 1800,
        reportUri: secJson.securityHeaders.config.csp.reportUri.uriLocation
      }
    } else if (options.ect === false) {
      headers.expectCt = false
    } else {
      // do nothing
    }
    if (options.sts === false) {
      headers.hsts = false
    } else if (options.sts.usePolicy && secJson.securityHeaders.config.strictTransportSecurity.enabled) {
      headers.hsts =
        {
          maxAge: secJson.securityHeaders.config.strictTransportSecurity.maxAge,
          includeSubDomains: secJson.securityHeaders.config.strictTransportSecurity.includeSubDomains,
          force: true
        }
    } else {
      headers.hsts =
        {
          maxAge: 15780000,
          includeSubDomains: true,
          force: true
        }
    }
    if (options.ieNoOpen === false) {
      headers.ieNoOpen = false
    }
    if (options.noCache === false) {
      headers.noCache = false
    }
    if (options.noSniff === false) {
      headers.noSniff = false
    }
    if (options.referrals && secJson.securityHeaders.config.referrals.enabled) {
      let choices = secJson.securityHeaders.config.referrals.options
      if (choices.unsafeUrl) {
        headers.referrerPolicy = { policy: 'unsafe-url' }
      } else if (choices.noOnDowngrade) {
        headers.referrerPolicy = { policy: 'no-referrer-when-downgrade' }
      } else if (choices.originOnly) {
        headers.referrerPolicy = { policy: 'same-origin' }
      } else if (choices.originOnCross) {
        headers.referrerPolicy = { policy: 'origin-when-cross-origin' }
      } else {
        headers.referrerPolicy = true
      }
    }
    if (options.xss === false) {
      headers.xssFilter = false
    } else {
      headers.xssFilter = true
    }
      return helmet(headers)
    }
  }
module.exports.setHeaders = setHeaders`
  return {
    modules: modules,
    code: code
  }
  } catch (e) {
    console.log('Could not write security headers file')
  }
}
function cacheBp(p) {
  try {
    modules.push ('redis')
    let code = `'use strict'
const secJson = require('../security.json')
const redis = require('redis')
// const PORT = require('./secrets').fetchSecret('CACHE_PORT') || 9000
const REDIS_PORT = require('./secrets').fetchSecret('REDIS_PORT')
const client = redis.createClient(REDIS_PORT)

module.exports = function cacheSec () {
  function setCacheHeaders () {
    let c = secJson.securityHeaders.caching.cacheControl
    let cc = ''
    for (let h = 0; h < c.length; h++) {
      cc = cc + c[h] + ', '
    }
    let v = secJson.securityHeaders.caching.vary
    let vv = ''
    for (let i = 0; i < v.length; i++) {
      vv = vv + v[i] + ', '
    }
    let cacheHeaders = {
      'Cache-Control': cc,
      pragma: secJson.securityHeaders.caching.pragma,
      vary: vv
    }
    return cacheHeaders
  }
  const setCache = function (route, fetchedThing) {
    if (secJson.caching.routeOverload === false && route !== undefined) {
      let error = new Error(\`Sorry! Route overload has been disabled for \${ route }\`)
      return error
    } else {
      try {
        client.setex(route, secJson.caching.ttl, fetchedThing)
      } catch (err) {
        return err
      }
    }
  }
  const getCache = async function (route, fetchedThing) {
    client.get(route, function (err, data) {
      if (err) throw err
      if (data !== null) {
        return data
      } else {
        return undefined
      }
    })
  }
  if (secJson.securityHeaders.caching.enabled === false) {
    let error = new Error('Caching is not enabled for this application')
    return error
  } else {
    let cacheHeaders = setCacheHeaders()
    return cacheHeaders
  }
}` 
  return {
    modules: modules,
    code: code
  }
} catch (e) {
    console.log('Could not write cache file')
  }
}
function valiateBp (p) {
  try {
    modules.push('validate.js')
    modules.push('sanitize-html')
    let code = `'use strict'
var secJson = require('../security.json')
let validate = require('validate.js')
let sanitizeHtml = require('sanitize-html')
var whitelists = require('./.whitelists.json')
const tls = require('tls')
/* Module obligations
  1. Browser checks?
  2. validate connection source (https?)
  3. header check => origin, host, referrer
  4. javascript, html, css sanitization
  5. form inputs
  6. sessions (id, cookies)
  7. authentication
  8. authorization
  9. pristine data prior to storage in database
*/
let validationMessages = {}

function validated (whatToValidate, callback) {
  if (whatToValidate.includes('header')) {
    return function headerCheck (requestHeaders, callback) {
      let whitelistRequired = secJson.contentValidationPolicy.semanticValidation.whitelistRequired
      // for each header in requestHeaders
      for (let header in requestHeaders) {
        // check to see if the header requires a whitelist
        // then check to see if THAT header's whitelist actually exists
        if (whitelistRequired.includes(header)) {
          if (whitelists[header]) {
            // check to see if the VALUE of THAT header is on the whitelist
            if (whitelists[header].includes(requestHeaders[header])) {
              // send 'valid' to the callback
              callback(null, 'valid')
            } else {
              // if it isn't, send an error to the callback function
              let error = \`\${ requestHeaders[header] } is invalid in header \${ header } \`
              error.status = 401
              callback(error)
            }
          } else {
            // otherwise, report an error to the call back function that a whitelist for THAT header could not be found
            let error = \`Unable to check \${ header } 's whitelist to validate \${requestHeaders[header]}\`
    error.status = 500
    callback(error, requestHeaders[header])
  }
        } else {
  // if the header does not require a whitelist, report a MESSAGE in the callback that the header does not require a whitelist and its value was not validated
  let message = { [header]: \`Header \${header} does not require validation\` }
  validationMessages = message
  callback(null, message)
}
      }
    }
  } else if (whatToValidate.includes('form')) {
  return function formValidator(form, rules) {
    // build the constraints object for each element in the rules
    let constraints = {}
    function passwordPolicy() {
      return {
        presence: true,
        length: {
          minimum: secJson.accessControlsPolicy.authenticationPolicy.passwords.minLen,
          maximum: secJson.accessControlsPolicy.authenticationPolicy.passwords.maxLen
        },
        format: secJson.accessControlsPolicy.authenticationPolicy.passwords.regex
      }
    }
    for (let element in rules.fields) {
      let valid = Object.keys(rules.fields[element].validation)
      let values = rules.fields[element].validation
      if (rules.fields.password) {
        constraints.password = passwordPolicy()
      }
      if (valid.includes('required')) {
        constraints[element] = { presence: true }
      }
      if (valid.includes('length')) {
        constraints[element] = { length: { is: values.length } }
      }
      if (rules.fields.includes('email') || valid.includes('email')) {
        constraints[element] = { email: true }
      }
      if (valid.includes('matches')) {
        constraints[element] = { equality: values.matches }
      }
      if (valid.includes('excludes')) {
        constraints[element] = { exclusion: { within: values.excludes } } // either a list (array) or an object
      }
      if (valid.includes('format')) {
        constraints[element] = { format: values.format } // matches regular expression pattern
      }
      if (valid.includes('includes')) {
        constraints[element] = { inclusion: { within: values.includes } } // either a list (array) or object
      }
      if (valid.includes('url')) {
        constraints[element] = { url: true }
      }
      let check = validate({ element: form.body[element] }, constraints[element]) // validate that the value for that element matches the constraints defined in the rules
      // convert elements to their correct type if needed
    }
  }
} else if (whatToValidate.includes('authentication')) {
  return function authenticationCheck(user, callback) {

  }
} else if (whatToValidate.includes('authorization')) {
  return function authorizationCheck(role, callback) {

  }
} else if (whatToValidate.includes('session')) {
  return function sessionCheck(sessionId, callback) {

  }
} else if (whatToValidate.includes('connection')) {
  return function connectionCheck(requestOrigin, callback) {
    // returns an error to the callback if the server is configured in a way that would contribute to a successful downgrade attack.
    // Downgrade attacks happen like this:
    // 1. Client uses weak or insecure SSL ciphers and the server DOESN'T reject it
    let message = \`These are the currently supported ciphers: \${tls.getCiphers()}\`
    validationMessages = { [message]: message }
    // 2. Sever offers both HTTP and HTTPS applications and DOES NOT redirect from HTTP
    // 3. Server DOES not have HSTS enabled (thus not forcing a redirect from HTTP)

    // HOWEVER if the application provides an HTTPS service AND has the HSTS header enabled, this check should pass
  }
} else if (whatToValidate.includes('view')) {
  return function sanitizeView(html, callback) {
    let clean = sanitizeHtml(html)
    return clean
  }
} else {
  let message = 'Validation failed'
  return message
}
}
/* -----------------------------------------Content Validation-------------------------------------- */
function contentValidation(obj, rules) {
  let constraints = {}
  validate.validators.unique = function (value, options, key, attributes) {
    console.log(value)
  }
  function authSchema() {
    for (let attrs in rules) {
      if (rules[attrs] === 'password' && secJson.accessControlsPolicy.enabled && secJson.accessControlsPolicy.authenticationRequired) {
        constraints.password.presence = true
        constraints.password.format = {
          pattern: secJson.accessControlsPolicy.authenticationPolicy.password.matches,
          flags: 'i',
          message: 'That is not a valid password'
        }
        constraints.password.length = {
          is: secJson.accessControlsPolicy.authenticationPolicy.password.length,
          wrongLength: 'Needs to be %{count} characters'
        }
      }
      if (rules[attrs] === 'email' && secJson.accessControlsPolicy.enabled && secJson.accessControlsPolicy.authenticationRequired) {
        constraints.email.presence = true
        constraints.email.email = true
      }
    }
    return constraints
  }

  function syntaxCheck() {
    for (let rule in rules) {
      for (let object in obj) {
        if (rules[rule].type === 'string') {
          validate.isString(obj[object])
        } else if (rules[rule].type === 'date' || rules[rule].type === 'Date') {
          validate.isDate(obj[object])
        } else if (rules[rule].type === 'array' || rules[rule].type === 'Array') {
          validate.isArray(obj[object])
        } else if (rules[rule].type === 'object' || rules[rule].type === 'Object') {
          validate.isObject(obj[object])
        } else if (rule[rule].type === 'boolean' || rules[rule].type === 'Boolean') {
          validate.isBoolean(obj[object])
        } else if (rules[rule].type === 'number' || rules[rule].type === 'Number') {
          validate.isNumber(obj[object])
        } else if (rules[rule].type === 'integer' || rules[rule].type === 'Integer') {
          validate.isInteger(obj[object])
        } else if (rules[rule].type === 'function' || rules[rule].type === 'Function') {
          // Not recommended to allow arbitrary functions to be passed as arguments
          validate.isFunction(obj[object])
        } else if (typeof obj[object] !== (rules[rule].type).toString()) {
          let err = new Error(\`Invalid input type. Expected \${rules[rule].type}. Instead found \${(typeof obj[object])}\`)
          return err
        } else {
          let error = new Error(\`Invalid input type. Expected \${rules[rule].type}. Instead found \${(typeof obj[object])}\`)
          return error
        }
      }
    }
  }
  if (!validate.isObj(obj) || !validate.isObj(rules)) {
    const err = new Error(\`Invalid Type Found. Cannot validate \${obj} against \${rules}\`)
    return err
  } else {
    let validationState = {}
    // let's build the ruleset
    for (let r in rules) {
      // check to see if the attribute is required
      if (rules[r] === 'required') {
        constraints[rules[r]].presence = true
      }
      // now let's do local auth
      for (let p = 0; p < secJson.accessControlsPolicy.authenticationPolicy.supportedMethods.length; p++) {
        if (secJson.accessControlsPolicy.authenticationPolicy.supportedMethods[p] === 'uname/passwd' || secJson.accessControlsPolicy.authenticationPolicy.supportedMethods === 'local') {
          constraints.password = authSchema().password
          constraints.email = authSchema().email
        }
      }
      // now more generic constraints
      if (rules[r] === 'unique') {
        constraints[rules[r]].unique = true
      }
      if (rules[r] === 'format') {
        constraints[rules[r]].format = rules[r].format
      }
      if (rules[r] === 'length') {
        constraints[rules[r]]['length'].is = rules[r].length
      }
      if (rules[r] === 'email') {
        constraints[rules[r]].email = true
      }
      if (rules[r] === 'date' || rules[r] === 'datetime') {
        constraints[rules[r]].datetime = true
      }
      if (rules[r] === 'matches') {
        constraints[rules[r]].equality = rules[r].matches
      }
    }
    syntaxCheck()
    validate(obj, constraints)
    return validationState
  }
}
module.exports = {
  validated: validated
}`
    let code2 = `{
    "origin": ["'https://localhost:8080'"],
    "host": ["'localhost:8080'"],
    "referers": [ "'http://localhost:3000'", 
                    "'https://localhost:8080/'", 
                    "'https://localhost:8080/login'",
                    "'http://localhost:3000/login'",
                    "'https://localhost:8080/register'",
                    "'http://localhost:3000/register'",
                    "'https://localhost:8080/thanks'",
                    "'http://localhost:3000/thanks'",
                    "'https://localhost:8080/profile'",
                    "'http://localhost:3000/profile'"
                ],
    "csp": "'secJson.securityHeaders.config.csp'"
}`
  return {
    modules: modules,
    code: code,
    code2: code2
  }
  } catch (e) {
    console.log('Could not write validation file')
  }
}
function dbBp (p) {
  try {
    modules.push('mongoose')
    let code = `'use strict'
let secJson = require('../security.json')
const mongoose = require('mongoose')
const dbConnect = require('./secrets').fetchSecret('DB_CONNECTION')

module.exports = function dbSec () {
  if (!secJson.dbSecurityPolicy.enabled) {
    throw new Error(\`Could not establish connection to database.Database security policy is: \${ secJson.dbsecurityPolicy.enabled }\`)
  }
  // create the connection
  mongoose.connect(dbConnect)
  let db = mongoose.connection
  db.on('error', console.error.bind(console, 'connection error:'))
  let schemaObject = {}
  let setSchema = function (name, schema) {
    schemaObject[name] = mongoose.model(name, schema)
    return schemaObject[name]
  }

  let createRecord = function (name, data, callback) {
    let Model = name
    Model.create(data, function (error, record) {
      if (error) {
        return callback(error)
      } else {
        return callback(null, record)
      }
    })
  }
  return {
    setSchema: setSchema,
    createRecord: createRecord
  }
}`
return {
  modules: modules,
  code: code
}
  } catch (e) {
    console.log('Could not create database security file')
  }
}
function connectBp (p) {
  try {
    let code = `'use strict'
require('dotenv').config()
const secJson = require('../security.json')
// const validInput = require('./validation').validInput()
const fs = require('fs')
const https = require('https')
const http = require('http')
const cert = require('./secrets').fetchSecret('CERTIFICATE')
const key = require('./secrets').fetchSecret('PRIV_KEY')
// const ca = require('./secrets').fetchSecret('CERT_AUTH')
const { constants } = require('crypto')
// const ciphers => use default node ciphers for now. See node docs if you want to change this
const port = require('./secrets').fetchSecret('PORT') || 8080

// this module is concerned with the establishment and maintenance of https connections to the server && provides redirect for any attempted connections to non-secure port(s)

/* NOTE: this module assumes you have already created certificates required. Be sure to add their absolute paths to your .env file as CERTIFICATE and PEM respectively */
function cb (err, c, p) {
  if (c instanceof Error) return console.log(\`\${ err }: \${ c } \`)
  else return console.log(\`\${ err }: \${ p } \`)
}
const secureServer = function (app, callback) {
  if (cert instanceof Error || key instanceof Error) {
    const error = new Error(\`Could not create a secure server\`)
    cb(error, cert, key)
  }
  if (callback && typeof callback === 'function') {
    callback()
  }
  const options = {
    secureOptions: constants.SSL_OP_NO_TLSv1,
    key: fs.readFileSync(key),
    cert: fs.readFileSync(cert),
    // ca: fs.readFileSync(ca),
    // ciphers: ciphers => using default node ciphers
    honorCipherOrder: true
  }
  if (app) {
    return https.createServer(options, app).listen(port)
  } else {
    callback = function (request, response) {
      console.log(\`I'm listening on port \${request.port}\`)
    response.send('Hello')
  }
    return https.createServer(options, callback).listen(port)
}
}
const redirectHttp = (app, callback) => {
  if (secJson.connectionPolicy.redirectSecure) {
    if (callback) {
      callback()
    }
    if (app) {
      return http.createServer(app, function (request, response) {
        response.writeHead(307, { Location: \`https://\${secJson.hostname}:\${port}\${request.url}\` })
        response.end()
      }).listen(3000)
    } else {
      return http.createServer(function (request, response) {
        response.writeHead(307, { Location: \`https://\${secJson.hostname}:\${port}\${request.url}\` })
        response.end()
      }).listen(3000)
    }
  } else {
    let err = new Error('Redirection not configured by security policy')
    return err
  }
}
// future release =>
/*
const certPin(cert) {
  function sha256(s) {
  return crypto.createHash('sha256').update(s).digest('base64');
}
const options = {
  hostname: 'github.com',
  port: 443,
  path: '/',
  method: 'GET',
  checkServerIdentity: function(host, cert) {
    // Make sure the certificate is issued to the host we are connected to
    const err = tls.checkServerIdentity(host, cert);
    if (err) {
      return err;
    }

    // Pin the public key, similar to HPKP pin-sha25 pinning
    const pubkey256 = 'pL1+qb9HTMRZJmuC/bB/ZI9d302BYrrqiVuRyW+DGrU=';
    if (sha256(cert.pubkey) !== pubkey256) {
      const msg = 'Certificate verification error: ' +
        \`The public key of '\${cert.subject.CN}' \` +
        'does not match our pinned fingerprint';
      return new Error(msg);
    }

    // Pin the exact certificate, rather then the pub key
    const cert256 = '25:FE:39:32:D9:63:8C:8A:FC:A1:9A:29:87:' +
      'D8:3E:4C:1D:98:DB:71:E4:1A:48:03:98:EA:22:6A:BD:8B:93:16';
    if (cert.fingerprint256 !== cert256) {
      const msg = 'Certificate verification error: ' +
        \`The certificate of '\${cert.subject.CN}' \` +
        'does not match our pinned fingerprint';
      return new Error(msg);
    }

    // This loop is informational only.
    // Print the certificate and public key fingerprints of all certs in the
    // chain. Its common to pin the public key of the issuer on the public
    // internet, while pinning the public key of the service in sensitive
    // environments.
      do {
        console.log('Subject Common Name:', cert.subject.CN);
        console.log('  Certificate SHA256 fingerprint:', cert.fingerprint256);

        hash = crypto.createHash('sha256');
        console.log('  Public key ping-sha256:', sha256(cert.pubkey));

        lastprint256 = cert.fingerprint256;
        cert = cert.issuerCertificate;
      } while (cert.fingerprint256 !== lastprint256);
    },
  }
}
*/
module.exports = {
  secureServer: secureServer,
  redirectHttp: redirectHttp
}`
  return {
    code: code
  }
  } catch (e) {
    console.log('Could not create connection security file')
  }
}
function corsBp (p) {
  try {
    modules.push('cors')
    let code = `'use strict'
const cors = require('cors')
const secJson = require('../security.json')

/* Here we need to distinguish between non-senstive and sensitive operations; anyone can make a GET request; otherwise, the more sensitive the operation (PUT, POST, PATCH), the more stringent the whitelist. As an example, mysite.foo.bar should be able to make a GET request...I don't need to whitelist that out because it's a non-sensitive operation (with some conditions, like credentials) however we DO need to put HTTPS://mysite.foo.bar:8080 on our whitelist if we're going to allow it to make changes to our server. FOR THAT REASON, I would HIGHLY recommend NOT allowing ALL subdomains of a host on your whitelist, but rather a few, very specific routes on a host */

module.exports = function corsConfig () {
  if (secJson.resourceSharingPolicy.corsSettings.enabled === false) {
    let error = new Error('CORS disabled by policy. Same-origin policy remains in effect')
    console.log(error)
    return error
  }
  let w = secJson.resourceSharingPolicy.corsSettings.config.whitelist
  // if (secJson.resourceSharingPolicy.corsSettings.enabled === true && w === []) {
  //   // Overly permissive whitelist => Access-Control-Allow-Origin *, for all methods BAD BAD BAD!
  //   w = [\`https://\${secJson.hostname}:8080\`]
    // }
    // Now let's parse the whitelist looking for subdomain declarations
    var backslash = "\\."
    const subdomainTransform = function (whitelist) {
      if (whitelist.includes('*')) {
        whitelist = whitelist.substr(1)
        whitelist = whitelist.split('.').join(backslash)
        whitelist = \`/\${whitelist}$/\`
      }
      return whitelist
    }
    for (var i = 0; i < w.length; i++) {
      w[i] = subdomainTransform(w[i])
    }

    var corsOptions = {}
    if (w.length === 0) {
      corsOptions = {
        origin: '*',
        methods: ['GET', 'OPTIONS', 'HEAD'],
        credentials: true,
        preflightContinue: true,
        optionsSuccessStatus: 200
      }
      // set CORS headers based upon the whitelist
    } else {
      corsOptions = {
        origin: function (origin, cb) {
          // check to see if origin is on the whitelist
          if (w.includes(origin)) {
            cb(null, true)
          } else {
            cb(new Error('Not allowed by CORS'))
          }
        },
        methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
        allowedHeaders: ['none'],
        credentials: true,
        maxAge: secJson.resourceSharingPolicy.corsSettings.config.preflightRequests.maxAge,
        preflightContinue: true,
        optionsSuccessStatus: 200
      }
    }
    return cors(corsOptions)
  }

// ------------------pre-flighting: add options handler ahead of your other unsafe methods-------------*/
// app.options('*', cors()) // enable pre-flight request for all routes & methods across the board`
  return {
    modules: modules,
    code: code
  }
  } catch (e) {
    console.log('Could not write cors security policy')
  }
}
function logBp (p) {
  try {
    modules.push('winston')
    let code = `'use strict'
let winston = require('winston')
let p = require('../security.json')
const tsFormat = () => (new Date()).toLocaleTimeString()
let levels = {}
/* ---------------------------------------Logging------------------------------------------------- */
if (p.loggingPolicy.levelsSupported === 'custom') { levels = { levels: p.loggingPolicy.levels } }

var options = {
  file: {
    level: 'info',
    filename: \`\${ p.loggingPolicy.logCollection.storage }\`,
    timestamp: tsFormat,
    handleExceptions: true,
    json: true,
    maxsize: 5242880, // 5MB
    maxFiles: 5,
    colorize: true
  },
  console: {
    level: 'debug',
    handleExceptions: true,
    timestamp: tsFormat,
    json: true,
    colorize: true
  }
}

const logger = winston.createLogger({
  levels: levels.levels,
  transports: [
    new winston.transports.File(options.file),
    new winston.transports.Console(options.console)
  ],
  exitOnError: false // do not exit on handled exceptions
})

module.exports.logger = logger`
  return {
    modules: modules,
    code: code
  }
  } catch (e) {
    console.log('Could not create logging file')
  }
}

function wbp (code, pathToFile) {
  var secFolder = './security'
  if(!fs.existsSync(secFolder)){
    fs.mkdir(secFolder, function(err) {
      if (err) {
        // console.log('Could not create security file')
        return err
      }
    })
  }
  let wbp = fs.createWriteStream(pathToFile, { flag: 'wx' })
  // for (var c = 0; c < (code.allModules).length; c++) {
  //   wbp.write(code.allModules[c])
  // }
  // wbp.write('var secJson = require(\'./security.json\') //may need to adjust this to the actual location of your policy file\n')
  if (pathToFile === './security.js') {
    code = code.slice(0, -2)
    code = code + `\n}\n`
  }
  wbp.write(code)
  wbp.close()
}

async function writeBoilerplate (policy) {
  try {
    let securityFile = `'use strict'

module.exports = {\n`
    if (policy.appDependencies.enabled === true) {
      securityFile = securityFile + `dependencies: require('./security/dependencies'),\n`
      await wbp(appDepBp(policy.appDependencies).code, './security/dependencies.js')
    } else {
      console.log('Skipping app dependencies')
    }
    if (policy.accessControlsPolicy.enabled === true) {
      securityFile = securityFile + `auth: require('./security/authentication'),\n`
      securityFile = securityFile + `fireAuth: require('./security/fire_auth'),\n`
      await wbp(accessCtrlBp(policy.accessControlsPolicy).code, './security/authentication.js')
      await wbp(firebaseBp().code, './security/fire_auth.js')
    } else {
      console.log('Skipping access controls')
    }
    if (policy.secretStorage.enabled === true) {
      securityFile = securityFile + `secrets: require('./security/secrets'),\n`
      await wbp(secretBp(policy.secretStorage).code, './security/secrets.js')
    } else {
      console.log('Skipping secrets management')
    }
    if (policy.formProtection.enabled === true) {
      securityFile = securityFile + `forms: require('./security/forms'),\n`
      await wbp(formBp(policy.formProtection).code, './security/forms.js')
    } else {
      console.log('Skipping forms protection')
    }
    if (policy.sessionPolicy.enabled === true) {
      securityFile = securityFile + `sessions: require('./security/sessions'),\n`
      await wbp(sessionBp(policy.sessionPolicy).code, './security/sessions.js')
    } else {
      console.log('Skipping session management')
    }
    if (policy.apiPolicy.enabled === true) {
      securityFile = securityFile + `api: require('./security/api'),\n`
      await wbp(apiBp(policy.apiPolicy).code, './security/api.js')
    } else {
      console.log('Skipping api management')
    }
    if (policy.securityHeaders.enabled === true) {
      securityFile = securityFile + `headers: require('./security/headers'),\n`
      await wbp(headersBp(policy.securityHeaders).code, './security/headers.js')
    } else {
      console.log('Skipping headers')
    }
    if (policy.securityHeaders.caching.enabled === true) {
      securityFile = securityFile + `cache: require('./security/cache'),\n`
      await wbp(cacheBp(policy.securityHeaders.caching).code, './security/cache.js')
    } else {
      console.log('Skipping caching')
    }
    if (policy.contentValidationPolicy.enabled === true) {
      securityFile = securityFile + `validation: require('./security/validation'),\n`
      await wbp(valiateBp(policy.contentValidationPolicy).code, './security/validation.js')
      await wbp(valiateBp(policy.contentValidationPolicy).code2, './security/.whitelists.json')
    } else {
      console.log('Skipping validation')
    }
    if (policy.dbSecurityPolicy.enabled === true) {
      securityFile = securityFile + `database: require('./security/database'),\n`
      await wbp(dbBp(policy.dbSecurityPolicy).code, './security/database.js')
    } else {
      console.log('Skipping databases')
    }
    if (policy.connectionPolicy.enabled === true) {
      securityFile = securityFile + `connections: require('./security/connections'),\n`
      await wbp(connectBp(policy.connectionPolicy).code, './security/connections.js')
    } else {
      console.log('Skipping secure connections')
    }
    if (policy.resourceSharingPolicy.corsSettings.enabled === true) {
      securityFile = securityFile + `cors: require('./security/cors'),`
      await wbp(corsBp(policy.resourceSharingPolicy).code, './security/cors.js')
    } else {
      console.log('Skipping cors')
    }
    if (policy.loggingPolicy.enabled === true) {
      securityFile = securityFile + `logging: require('./security/logging'),\n`
      await wbp(logBp(policy.loggingPolicy).code, './security/logging.js')
    } else {
      console.log('Skipping logging')
    }
    await wbp(securityFile, './security.js')
    var msg = chalk.magenta(`Successfully wrote boilerplate code for policy ${policy.policyId}\n`)
    return {
      'modules': modules,
      'message': msg,
      'pathToFile': pathToBoilerPlate }
  } catch (e) {
    throw e
  }
}
module.exports.matches = matches
module.exports.diff = diff
module.exports.writeBoilerplate = writeBoilerplate
module.exports.removeModules = removeModules
