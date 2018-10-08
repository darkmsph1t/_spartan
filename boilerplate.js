'use strict'
var chalk = require('chalk')
var { spawn } = require('child_process')
var fs = require('fs')
var path = require('path')
var pathToBoilerPlate = path.resolve('./security.js')

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
    return `'use strict'
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
    
  } catch (e) {
    console.log('Could not write application dependencies file')
  }
}
function apiBp(p) {
  try {
    return `'use strict'

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
}
`
  } catch (e) {
    console.log('Could not write api security file')
  }
}
function accessCtrlBp (p) {
  try {
    return `'use strict'
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
`
  } catch (e) {
    console.log('Could not write access control file')
  }
}
function secretBp(p) {
  try {
    return `'use strict'
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
  } catch (e) {
    console.log('Could not write secrets management file')
  }
}
function formBp (p) {
  try {
  return `'use strict'
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
} catch (e) {
    console.log('Could not write forms protection file')
  }
}
function sessionBp (p) {
  try {
    return `'use strict'
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
  } catch (e) {
    console.log('Could not write session management file')
  }
}
function headersBp (p) {
  try {
    return `'use strict'
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
module.exports.setHeaders = setHeaders
`
  } catch (e) {
    console.log('Could not write security headers file')
  }
}
function cacheBp (p) {
  try {
    `'use strict'
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
  const setCache = async function (route, fetchedThing) {
    if (secJson.caching.routeOverload === false && route !== undefined) {
      let error = new Error(\`Sorry! Route overload has been disabled for \${ route }\`)
      return error
    } else {
      try {
        await client.setex(route, secJson.caching.ttl, fetchedThing)
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
}
`
  } catch (e) {
    console.log('Could not write cache file')
  }
}
function valiateBp (p) {
  try {
    return `'use strict'
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
}
`
  } catch (e) {
    console.log('Could not write validation file')
  }
}
function dbBp (p) {
  try {
    return `'use strict'
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
}
`
  } catch (e) {
    console.log('Could not create database security file')
  }
}
function connectBp (p) {
  try {
    return `'use strict'
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
};
}
*/

module.exports = {
  secureServer: secureServer,
  redirectHttp: redirectHttp
}
`
  } catch (e) {
    console.log('Could not create connection security file')
  }
}
function corsBp (p) {
  try {
    return `'use strict'
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
// app.options('*', cors()) // enable pre-flight request for all routes & methods across the board
`
  } catch (e) {
    console.log('Could not write cors security policy')
  }
}
function logBp (p) {
  try {
    return `'use strict'
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

module.exports.logger = logger
`
  } catch (e) {
    console.log('Could not create logging file')
  }
}
async function interpreter (p, mods) {
  try {
  } catch (e) {
    console.log(chalk.yellow(`There was a problem interpreting the policy and boilerplate code could not be written, ${e}`))
  }
}

function wbp (code, pathToFile) {
  
  var wbp = fs.createWriteStream(pathToFile, { flag: 'wx' })
  var convert = '\'use strict\';\n'
  wbp.write(convert)
  for (var c = 0; c < (code.allModules).length; c++) {
    wbp.write(code.allModules[c])
  }
  wbp.write('var secJson = require(\'./security.json\') //may need to adjust this to the actual location of your policy file\n')
  wbp.write(code.finalCode)
  wbp.close()
}

async function writeBoilerplate (policy) {
  try {
    if (policy.appDependencies.enabled === true) {
      wbp(appDepBp(policy.appDependencies), './security/dependencies.js')
    }
    if (policy.aceessControlsPolicy.enabled === true) {
      wbp(accessCtrlBp(policy.aceessControlsPolicy), './security/authentication.js')
    }
    if (policy.secretStorage.enabled === true) {
      wbp(secretBp(policy.secretStorage), './security/secrets.js')
    }
    if (policy.formProtection.enabled === true) {
      wbp(formBp(policy.formProtection), './security/forms.js')
    }
    if (policy.sessionPolicy.enabled === true) {
      wbp(sessionBp(policy.sessionPolicy), './security/sessions.js')
    }
    if (policy.apiPolicy.enabled === true) {
      wbp(apiBp(policy.apiPolicy), './security/api.js')
    }
    if (policy.securityHeaders.enabled === true) {
      wbp(headersBp(policy.securityHeaders), './security/headers.js')
    }
    if (policy.securityHeaders.caching.enabled === true) {
      wbp(cacheBp(policy.securityHeaders.caching), './security/cache.js')
    }
    if (policy.contentValidationPolicy.enabled === true) {
      wbp(valiateBp(policy.contentValidationPolicy), './security/valiation.js')
    }
    if (policy.dbSecurityPolicy.enabled === true) {
      wbp(dbBp(policy.dbSecurityPolicy), './security/database.js')
    }
    if (policy.connectionPolicy.enabled === true) {
      wbp(connectBp(policy.connectionPolicy), './security/connections.js')
    }
    if (policy.resourceSharingPolicy.corsSettings.enabled === true) {
      wbp(corsBp(policy.resourceSharingPolicy), './security/cors.js')
    }
    if (policy.loggingPolicy.enabled === true) {
      wbp(logBp(policy.loggingPolicy), './security/logging.js')
    }
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
