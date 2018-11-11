'use strict'
const secJson = require('../security.json').sessionPolicy
const secrets = require('./secrets')
const session = require('express-session')
const csrf = require('csurf')
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

module.exports = {
  sessioner: () => {
    // session.Session.prototype.login = function (user, callback) {
    //   const request = this.request
    //   request.session.regenerate(function (err) {
    //     if (err) {
    //       callback(err)
    //     }
    //   })
    // }
    if (secJson.enabled === false) {
      let error = new Error('sessions/disabled-by-policy')
      error.message = 'Session management is disabled by policy'
      return error
    }
    if (secJson.config.duration.idle) { // destroys the session after a period of idle time
      obj.resave = true
      obj.rolling = true
      obj.cookie = { maxAge: secJson.config.duration.idle }
    }
    if (secJson.config.cookies.sameSite) {
      obj.cookie = { sameSite: secJson.config.cookies.sameSite }
    }
    if (secJson.config.cookies.domain === null && secJson.config.cookies.path === '/' && secJson.config.cookies.secure === true) {
      obj.name = `${secJson.config.cookies.prefixes[0]}-${secJson.config.cookies.name}`
    } else if (secJson.config.cookies.secure === true) {
      obj.name = `${secJson.config.cookies.prefixes[1]}-${secJson.config.cookies.name}`
    }
    return session(obj) // actually sets up the session with the configured options
  },
  cookieMonster: (response, options, callback) => {
    response.clearCookie(options.name, options.options, function (err) {
      if (err) {
        return callback(err)
      }
    }) // destroys the session cookie
  },
  cookieMaker: (request, response, options, callback) => {
    // if required parameters are missing, error
    if (!options.name || !options.value) {
      let error = new Error('session/missing-params')
      error.message = 'Required parameters missing'
      callback(error, null)
    }
    // returns a new secure cookie if there's a secure server/connection
    if (request.secure === true) {
      options.options = { httpOnly: true }
      options.options = { secure: true }
      if (!options.options.domain && options.options.path === '/') {
        options.name = `_Host-${options.name}`
      }
      return response.cookie(options.name, options.value, options.options)
    } else {
      let error = new Error('session/insecure-connection')
      error.message = 'No secure cookies for you! insecure connection detected'
      callback(error, null)
    }
  },
  csrf: (options, callback) => {
    if (options === null) {
      let error = new Error('sessions/missing-csrf-options')
      error.message = 'An expected value was not found while trying to create a CSRF token'
      callback(error)
    } else if (typeof options.cookie !== 'boolean') {
      let error = new TypeError('sessions/option-type-incorrect')
      error.message = 'Incorrect type presented for csrf options'
      callback(error)
    }
    return csrf(options)
  }
}
