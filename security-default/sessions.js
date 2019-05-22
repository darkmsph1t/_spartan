'use strict'
let secJson = require('./security.json'),
    sessPolicy = secJson.sessionPolicy,
    {LogWriter, Bullhorn} = require('./logger'),
    sessLog = new LogWriter({console : false, file : true}),
    cookieProps = {},
    uuidv4 = require('uuid/v4'),
    proc = require('dotenv').config()

const lookup = (cookie, cb) => {
  // look up the session id in the database
  for (let c in cookieProps) {
    if (cookie.id === cookieProps[s] && cookie.maxAge > Date.now()) {
      return cb(null, true)
    } else {
      let err = new Error('sessions/id-not-from-server')
      err.message = 'The provided session identifier was not issued by this server. This may be an attempt at a session fixation attack'
      error.code = 'sessions/session-id-not-from-server'
      error.status = 'ERROR'
      error.level = 'ERROR'
      return cb(err, false)
    }
  }
  // if the id is 'found' && it's valid, return success = true
  // else generate an error and return the error & success = false
}

class StoneWall {
  constructor () {

  }
  secureSession(name, store) {
    let cookieParams = sessPolicy.config.cookies,
        duration = sessPolicy.config.duration
    return {
      secret : process.env.COOKIE_SECRET,
      store : store ? store : null,
      name : (() => {
        if(cookieParams.prefixes.includes('_Host')) {
          return `_Host-${name}`
        } else if ( cookieParams.prefixes.includes('_Secure')) {
          return `_Secure-${name}`
        } else {
          return name
        }
      })(),
      genid : () => {
              return uuidv4()
      },
      cookie : {
        httpOnly: cookieParams.httpOnly === true ? true : false,
        secure: cookieParams.secure === true || cookieParams.prefixes.includes('_Host') || cookieParams.prefixes.includes('_Secure') ? true : false,
        hostOnly: cookieParams.hostOnly === true ? true : false,
        domain: cookieParams.prefixes.includes('_Host') ? false : cookieParams.domain,
        maxAge: (() => {
          if (duration.idle && (duration.idle*1000) < cookieParams.maxAge) {
            return duration.idle * 1000
          } else if (duration.ttl && (duration.ttl*1000) < cookieParams.maxAge) {
            return duration.ttl * 1000
          } else {
            return Date.now() + cookieParams.maxAge
          }
        })(),
        path: cookieParams.prefixes.includes('_Host') ? '/' : cookieParams.path,
        sameSite: cookieParams.sameSite
      },
      resave : false,
      rolling: duration.automaticRenewal === false ? false : true,
      saveUninitialized : (() => {
        return this.rolling === true ? true : false
      })(),
      unset : 'destroy'
    }
  }
  logoutOnExpire(request, response, next) {
    if (request.session && request.session.id && request.session.cookie.expires < Date.now()) {
      request.session.destroy(err => {
        if (err) {
          console.log('ooh girl, bye!')
          return next(err)
        }
      })
    }
    next()
  }
  invalidateId(request, response, callback) {
    if (request.sessionID) {
      try{
        request.session.destroy(err => {
          if (err) {
            err.message = 'Could not remove session from session store'
            err.status = 'ERROR'
            err.level = 'ERROR'
            err.code = 'session/failure-to-invalidate-id'
            sessLog({ class: 'SESSION', subclass: 'SESSION Id Invalidation', type: err.level, context: JSON.stringify(request), message: `${err.code} : ${err.message}, (${err.status})` })
            return callback(err, null)
          } else {
            let m = `${request.sessionID} was destroyed`
            return callback(null, m)
          }
        })
      } catch(err) {
        err.status = 400
        return callback(err, null)
      }
    }
  }
  /**
   * @name getsessionLimits
   * @description fetches session limits currently in place for a given session id
   * @param {String} id 
   * @returns {Object} session limits
   */
  getsessionLimits(id) {
    let sessionDuration = sessPolicy.config.duration
    lookup({ id: id }, (err, success) => {
      if (err) {
        return err
      }
    })
    if (sessionDuration.ttl === null) {
      let message = `the id ${id} has an infinite session duration.`
      console.log(message)
      return {
        ttl: null,
        idle: null,
        automaticRenewal: null,
        message: message
      }
    } else {
      let message = `id ${id} has a ttl of ${sessionDuration.ttl}`
      console.log(message)
      return {
        ttl: sessionDuration.ttl,
        idle: sessionDuration.idle,
        automaticRenewal: sessionDuration.automaticRenewal,
        message: message
      }
    }
  }
  /**
   * @name sessionLimits
   * @param {String} id session duration limits will apply to this id
   * @param {Object} [options] set ttl, idle timeout, invalidate on close
   */
  sessionLimits(id, options) {
    if (options) {
      // apply the limits defined in the options object to the id
    } else { // use the defaults in the security policy
      let sessionDuration = sessPolicy.config.duration
      if (sessionDuration.ttl === null) {
        console.log(`the id ${id} has an infinite session duration. This is not recommended`)
      }
    }
  }
  /**
   * @name whoseMansIsThis
   * @description prevents session fixation attacks by validating that the provided session id was actually issued by the server
   * @param {String} sessionId decoded session id from cookie
   */
  whoseMansIsThis(request, cookie) {
    lookup(cookie, (err, success) => {
      if (err) {
        sessLog.writer({ class: 'SESSIONS', subclass: 'SESSION Id Invalid', level: err.level, context: { method: request.method, url: request.url, ip: request.ip, browser: request.header['user-agent'] }, message: `${err.code} : ${err.message}, (${err.level})` })
        return err
      } else {
        return success
      }
    })
  }
}

class CookieInspector {
  constructor() {
  }
  
  /**
   * @name frosting
   * @description provides the security config specified in the security policy
   * @returns {object}
   */
  frosting() {
    let cookieParams = sessPolicy.config.cookies,
        opts = {
          maxAge : Date.now() + cookieParams.maxAge,
          httpOnly : cookieParams.httpOnly,
          secure : cookieParams.secure,
          hostOnly : cookieParams.hostOnly,
          domain : cookieParams.domain,
          path : cookieParams.path,
          sameSite : cookieParams.sameSite
        }
    return opts
  }

  cookieMaker(name, value) {
    let cookieParams = sessPolicy.config.cookies
    return {
      name: (() => {
        if (cookieParams.prefixes.includes('_Host')) {
          return `_Host-${name}`
        } else if (cookieParams.prefixes.includes('_Secure')) {
          return `_Secure-${name}`
        } else {
          return name
        }
      })(),
      value : value,
      options: {
        httpOnly: cookieParams.httpOnly === true ? true : false,
        secure: cookieParams.secure === true || cookieParams.prefixes.includes('_Host') || cookieParams.prefixes.includes('_Secure') ? true : false,
        hostOnly: cookieParams.hostOnly === true ? true : false,
        domain: cookieParams.prefixes.includes('_Host') ? false : cookieParams.domain,
        maxAge: Date.now() + cookieParams.maxAge,
        path: cookieParams.prefixes.includes('_Host') ? '/' : cookieParams.path,
        sameSite: cookieParams.sameSite
      }
    }
  }
  /**
   * @description validates cookie settings to ensure that they are being handled securely
   * @param {Object} cookie 
   */
  cookieMonster(cookie, request, callback) {
    for(let c in cookie) {
      if(c.includes('JSESSION') ||
         c.includes('PHPSESS') ||
         c.includes('CFID') ||
         c.includes('CFTOKEN') ||
         c.includes('ASP.NET_SessionId')) {
          let message = `Found default value session id name, which is dangerous security practice. Recommend changing this value to something less obvious`
          let error = new Error('session/session-id-fingerprinting')
          error.message = message
          error.status = 'WARN'
          error.level = 'WARN'
          error.code = 'session/session-id-fingerprinting'
        sessLog.writer({ class: 'SESSION', subclass: 'SESSION Id Fingerprintng', type: error.status, level: error.level, context: 'N/A', message: `${error.code} : ${error.message} (${error.status})` })
          return callback(error, false)
        }
      if (cookie[c].length < 32) {
        let message = `Session Id length should be at least 128-bits (32 random characters) to prevent brute force enumeration`,
            error = new Error('session/session-id-length')
        error.code = 'session/session-id-length'
        error.level = 'WARN'
        error.status = 'WARN'
        error.message = message
        sessLog.writer({ class: 'SESSION', subclass: 'SESSION Id Length', type: error.status, level: error.level, context: 'N/A', message: `${error.code} : ${error.message} (${error.status})`})
        return callback(error, false)
      }
      if (!cookie[c].includes('HttpOnly') || !cookie[c].includes('Secure') || !cookie[c].includes('HostOnly')) {
        let message = `Found cookie without HttpOnly, Secure or HostOnly flags enabled, so it was transmitted insecurely. Be sure NOT to trust this cookie with sensitive data && purge this cookie as soon as possible to avoid misuse`
        let error = new Error('sessions/insecure-cookie-configuration')
        error.message = message
        error.status = 'WARN'
        error.level = error.status
        error.code = 'sessions/insecure-cookie-configuration'
        sessLog.writer({ class: 'SESSIONS', subclass: 'SESSION Id Invalid', type: error.status, level: error.level, context: JSON.stringify({ method: request.method, url: request.url, ip: request.ip, browser: request.headers['user-agent'] }), message: `${error.code} : ${error.message}, (${error.level})` })
        return callback(error, false)
      } 

    }
  }
}
module.exports = {
  CookieInspector : CookieInspector,
  StoneWall : StoneWall
}