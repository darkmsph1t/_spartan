'use strict'
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
      obj.name = `${ secJson.config.cookies.prefixes[0] } -${ secJson.config.cookies.name } `
    } else if (secJson.config.cookies.secure === true) {
      obj.name = `${ secJson.config.cookies.prefixes[1] } -${ secJson.config.cookies.name } `
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
      options.name = `_Host - ${ options.name }`
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
