'use strict'
    /* assumption => will not be using this to manage clientID/clientSecret negotiations...
    this is only for requests TO the application's API */

let RateLimiter = require('limiter').RateLimiter,
    numberRequestsAllowed = 150, // this should ultimately come from security.json
    periodRequestsAllowed = 'hour', // this should ultimately come from security.json
    requestTable = {},
    limiter,
    dotenv = require('dotenv').config(),
    path = require('path'),
    jwt = require('njwt'),
    fs = require('fs'),
    { LogWriter } = require('./logger'),
    apiLog = new LogWriter(
       {
        console: false, 
        file: true, 
        filters: {
          'key': [/[A-Za-z0-9]{32}/, 'KEY REDACTED'],
          'credit-card': [/^\d{4}-\d{4}-\d{4}-\d{4}$|\d{16}/, 'xxxx-xxxx-xxxx-0000'],
          'ssn': [/^\d{3}-\d{2}-\d{4}$|\d{9}/, 'YYY-ZZ-XXXX']
         }
        }),
    methOver = require(path.join(__dirname + '/security.json')).formProtection.config.allowMethodOverride
    apiLog.rotateLogs = 'weekly'
    const setRemaining = (key, remaining) => { // 
      requestTable[key] = remaining
    }
    const getRemaining = (key) => { // takes the key and does a lookup of remaining requests
      return requestTable[key]
    }
    const getKey = (key) => {
      if (Object.keys(requestTable).includes(key)) { // this should come from the database
        return {
          success : true,
          expires : Math.floor(Date.now()/1000) + (24*60*60*1000), // in seconds, expires 24 hours by default
          decodedKey : key
        }
      } else {
        return {
          success : false,
          expires : null,
          decodedKey : null
        }
      }
    }
    const revokeKey = (key) => {
      return `Key ${key} has been removed`
    }
    const checkToken = (req, cb) => { // let's plan to move this to the authentication workflow
      let token = req.headers['x-access-token'] || req.headers['authorization']
      if(token.startsWith('Bearer ')) {
        token = token.slice(7, token.length)
      }
      if(token) {
        jwt.verify(token, process.env.SECRET,(err, decoded) => { 
          if (err) {
            let error = new Error('api/problem-decoding-token')
            error.message = err.message
            error.status = 500 // Server Error
            error.code = 'api/problem-decoding-token'
            return cb(error, false, null)
          } else {
            if (!decoded.body.aud.includes(req.path)) {
              let error = new Error('api/invalid-request')
              error.message = 'You do not have permission to access this resource'
              error.status = 403 // Not Authorized
              error.code = 'api/invalid-request'
              return cb(error, false, error.message)
            } else if ((req.method === 'GET' && !decoded.body.scope.includes('read')) ||
                       (req.method === 'POST' && !decoded.body.scope.includes('create')) ||
                       ((req.method === 'PUT' || req.method === 'PATCH') && !decoded.body.scope.includes('update')) ||
                       (req.method === 'DELETE' && !decoded.body.scope.includes('delete'))) { // if the method/action matches the scope/action
              let error = new Error('api/illegal-action')
              error.message = 'You do not have permission to perform that action on this resource'
              error.status = 403
              error.code = 'api/illegal-action'
              return cb(error, false, error.message)
            } else {
              return cb(null, true, decoded)
            }
          }
        })
      } else {
        return cb(null, null, 'nothing to send')
      }
  }
    const checkKey = (req, options, cb) => { // let's plan to move this to the authentication workflow
      let key
      if (options.key) {
        key = options.key
      }
      if (req.protocol.includes(':')) {
        let p = req.protocol.split(':')
        req.protocol = p[0]
      }
      if (req.protocol !== 'https') {
        let error = new Error('api/insecure-key-transmission')
        error.status = 400 // Bad Request
        error.code = 'api/insecure-key-transmission'
        if (options && options.revokeKey) { // automatically revoke keys
          revokeKey(key)
          error.message = `The API key was transmitted via insecure means: ${req.protocol}. Key ${key} has been revoked and a new one should be generated.`
        } else {
          error.message = `The API key was transmitted via insecure means: ${req.protocol}. You should revoke this key's access and generate a new one`
        }
        return cb(error, false, error.message)
      }
      if(key) { // check key validity
        for (let k = 0; k < key.length; k++) {
          // lookup key in database
          setRemaining(key[k], 1) // remove prior to publish
          let findKey = getKey(key[k]) // <-- this should be options.fetchKey method which returns key with expiry
          // if key doesn't exist in the database, return an error
          if (findKey.success === false || key[k].length < 32) {
            let error = new Error('api/invalid-key')
            error.status = 403
            error.message = 'The key provided is invalid'
            error.code = 'api/invalid-key'
            return cb(error, false, error.message)
          } else if (findKey.expires !== 'never' && findKey.expires < Math.floor(Date.now() / 1000)) { // if key is expired (according to the database) return an error
            let error = new Error('api/expired-key')
            error.status = 403
            error.message = 'The key provided is expired'
            error.code = 'api/expired-key'
            return cb(error, false, error.message)
          } else if (!options.allowed.includes(req.method.toLowerCase())) { // if the requested action is outside of what the key grants, return an error
            let error = new Error('api/illegal-action')
            error.message = 'You do not have permission to do the requested action with the provided key'
            error.status = 403
            error.code = 'api/illegal-action'
            return cb(error, false, error.message)
          } else {
            return cb(null, true, 'yay!')
          }
        }
      }
    }
module.exports = {
  apiAccessCtrl : (request, options, callback) => { // covers authentication/authorization api concerns
    // API Key Validation
    try {
      let context = {
            from: request.ip,
            method: request.method,
            url: request.url,
            route: request.route,
            browser: request.headers['user-agent'],
            params: () => {
              return request.params || 'no params'
            },
            query: () => {
              return request.query || 'no query string'
            }
          }
      if (options.key) {
        checkKey(request, options, (err, success, message) => {
          if (err) {
            apiLog.writer({ class: 'API', subclass: 'Key Validation', type: 'ERROR', context: JSON.stringify(context), message: `${err.code} : ${err.message}, (${err.status})` })
            return callback(err, success, message)
          } else {
            apiLog.writer({ class: 'API', subclass: 'Key Validation', type: 'SUCCESS', context: context, message: `Validated API Key, 200` })
            return callback(null, success, message)
          }
        })
      } else {
        checkToken(request, (err, success, message) => {
          if (err) {
            apiLog.writer({ class: 'API', subclass: 'TOKEN Validation', type: 'error', context: context, message: `${err.code} : ${err.message}, (${err.status})` })
            return callback(err, success, message)
          } else {
            apiLog.writer({ class: 'API', subclass: 'TOKEN Validation', type: 'success', context: context, message: 'Validated Token' })
            return callback(null, success, message)
          }
        })
      }
    } catch (e) {
      return e
    }
  },
  /** 
   *   @param {Request} request  - The request object. Expects Express-style request object
   *   @param {object} options  - object containing allowed methods, keys
   *   @param {Function} callback (err, success): function containing any errors, success (boolean)
   *   @return {void}
   */
  apiMethodCheck : (request, options, callback) => {
    let context = {
          from: request.ip,
          method: request.method,
          url: request.url,
          route: request.route,
          browser: request.headers['user-agent'],
          params: () => {
            return request.params || 'no params'
          },
          query: () => {
            return request.query || 'no query string'
          }
        },
        safeMethods = ['GET', 'HEAD', 'OPTIONS', 'POST'],
        e = [],
         overloadHeaders
      if (request.headers['X-HTTP-METHOD'] !== undefined) {
        overloadHeaders = request.headers['X-HTTP-METHOD']
      } else if (request.headers['X-HTTP-METHOD-OVERRIDE'] !== undefined) {
        overloadHeaders = request.headers['X-HTTP-METHOD-OVERRIDE']
      } else if (request.headers['X-METHOD-OVERRIDE'] !== undefined){
        overloadHeaders = request.headers['X-METHOD-OVERRIDE']
      } else {
        overloadHeaders = undefined
      }
    for (let i = 0; i < options.allowed.length; i++) {
      if (!safeMethods.includes(options.allowed[i].toUpperCase())) {
        e.push(options.allowed[i])
      }
    }
    // if options.allowed is NOT one of the safe methods and there's no key, return an error
    if (options.key === undefined && e) {
      let error = new Error('api/missing-key')
      error.message = `An API key is required to use overload method ${e}`
      error.status = 400 // Bad Request
      error.code = 'api/missing-key'
      apiLog.writer({ class: 'API', subclass: 'METHOD Validation', type: 'ERROR', context: JSON.stringify(context), message: `${error.code} : ${error.message}, (${error.status})` })
      return callback(error, false)
    }
    if (methOver === false && !safeMethods.includes(request.method)) {
      let error = new Error('api/method-override-prohibited')
      error.message = `The method ${request.method} is not allowed by policy`
      error.status = 405
      error.code = 'api/method-override-prohibited'
      apiLog.writer({ class: 'API', subclass: 'METHOD Validation', type: 'ERROR', context: JSON.stringify(context), message: `${error.code} : ${error.message}, (${error.status})` })
      return callback(error, false)
    } else if (methOver === false && overloadHeaders !== undefined) {
        let error = new Error('api/method-override-prohibited')
        if (request.headers['X-HTTP-METHOD']) {
          error.message = `The method ${request.headers['X-HTTP-METHOD']} is prohibited by policy`
        } else if (request.headers['X-HTTP-METHOD-OVERRIDE']) {
          error.message = `The method ${request.headers['X-HTTP-METHOD-OVERRIDE']} is prohibited by policy`
        } else {
          error.message = `The method ${request.headers['X-METHOD-OVERRIDE']} is prohibited by policy`
        }
        error.status = 405
        error.code = 'api/method-override-prohibited'
      apiLog.writer({ class: 'API', subclass: 'METHOD Validation', type: 'ERROR', context: JSON.stringify(context), message: `${error.code} : ${error.message}, (${error.status})` })    
      return callback(error, false)     
    } else if (methOver === false && request.query['_method']) {
        let error = new Error('api/invalid-method-in-query-param')
        error.message = `Found method ${request.query['_method']} in query parameter. Method override is prohibited`
        error.status = 400 // Bad Request
        error.code = 'api/invalid-method-in-query-param'
        apiLog.writer({ class: 'API', subclass: 'METHOD Validation', type: 'ERROR', context: JSON.stringify(context), message: `${error.code} : ${error.message}, (${error.status})` })
        return callback(error, false)
    } else if (methOver && options) {
        if (!options.allowed.includes((request.method).toLowerCase())) {
          let error = new Error('api/invalid-method-on-resource')
          error.message = `The method ${request.method} was requested for this resource but is not allowed`
          error.status = 405
          error.code = 'api/invalid-method-on-resource'
          apiLog.writer({ class: 'API', subclass: 'METHOD Validation', type: 'ERROR', context: JSON.stringify(context), message: `${error.code} : ${error.message}, (${error.status})` })
          return callback(error, false)
        } else {
          apiLog.writer({ class: 'API', subclass: 'METHOD Validation', type: 'SUCCESS', context: context, message: `Method ${request.method} allowed, 200` })
          return callback(null, true)
        }
    } else {
      apiLog.writer({ class: 'API', subclass: 'METHOD Validation', type: 'SUCCESS', context: JSON.stringify(context), message: `Method ${request.method} allowed, 200` })
      return callback(null, true)
    }
  },
  apiRateLimit : (request, options, number, interval, callback) => {
    let context = {
      from: request.ip,
      method: request.method,
      url: request.url,
      route: request.route,
      browser: request.headers['user-agent'],
      params: () => {
        return request.params || 'no params'
      },
      query: () => {
        return request.query || 'no query string'
      }
    }
    if (number && interval) {
      limiter = new RateLimiter(number, interval)
    } else {
      number   = numberRequestsAllowed 
      interval = periodRequestsAllowed
    }

    if (options.instaBlock) {
      if (!options.key || typeof options.key !== 'string') { // dos protection...
          let error = new Error('api/cannot-block-without-key')
          error.message = `Key is missing or null, even though rate-limit has been reached. Cannot apply block to this route`
          error.status = 400 // Bad request
          error.code = 'api/cannot-block-without-key'
        apiLog.writer({ class: 'API', subclass: 'Key Validation', type: 'ERROR', context: JSON.stringify(context), message: `${error.code} : ${error.message}, (${error.status})` })
          return callback(error, null)
      }
      let startTime = options.instaBlock.from,
          currentTime = Date.now(),
          elapsedTime = currentTime - startTime

      if (elapsedTime < options.instaBlock.duration) { // apply the block
        limiter = new RateLimiter(number, interval, true)
        limiter.removeTokens(1, (err, remainingRequests) => {
          if (remainingRequests < 1) {
            let error = new Error('api/request-blocked')
            error.message = `Requests to this route are not allowed at this time. Please try again in ${((options.instaBlock.duration - elapsedTime)/(1000*60)).toFixed(0)} minutes`
            error.status = 429
            error.code = 'api/request-blocked'
            apiLog.writer({ class: 'API', subclass: 'Key Validation', type: 'ERROR', context: JSON.stringify(context), message: `${error.code} : ${error.message}, (${error.status})` })
            return callback(error, false)
          }
        })
      } else { // the block has expired and the request can proceed as normal
        apiLog.writer({ class: 'API', subclass: 'Key Validation', type: 'INFO', context: JSON.stringify(context), message: `Rate limiting access restrictions expired.` })
        return (null, true)
      }
    }
    if (!options.key || typeof options.key !== 'string') { // no key, but throttling
      // Deprecate requests per route
      limiter.removeTokens(1, (err, remainingRequests) => {
        if (options.throttle) {
          if(remainingRequests >= options.throttle.within) {
            apiLog.writer({ class: 'API', subclass: 'Key Validation', type: 'INFO', context: JSON.stringify(context), message: `${remainingRequests} to ${request.url} from ${request.ip}` })
            return callback(null, true) // let the request go through
          } else {
            limiter = new RateLimiter(options.throttle.slowDownTo, options.throttle.per)
            let message = `You are within the last few allowed requests for the allotted time period. Your rate limit has been changed to ${options.throttle.slowDownTo} requests per ${options.throttle.per}`
            apiLog.writer({ class: 'API', subclass: 'Key Validation', type: 'INFO', context: JSON.stringify(context), message: `Rate limiting access throttling in effect, (200)` })
            return callback(null, true, message)
          }
        } else {
          if (remainingRequests < 1) {
            let error = new Error('api/too-many-requests')
            error.message = 'you have exceeded the number of requests in the time period allotted.'
            error.status = 429 // Too Many Requests
            error.code = 'api/too-many-requests'
            apiLog.writer({ class: 'API', subclass: 'Key Validation', type: 'ERROR', context: JSON.stringify(context), message: `${error.code} : ${error.message}, (${error.status})` })
            return callback(error, false)
          } else { // allow request to go through
            apiLog.writer({ class: 'API', subclass: 'Key Validation', type: 'SUCCESS', context: JSON.stringify(context), message: `API Access request for ${request.url} from ${request.ip}, (200)` })
            return callback(null, true)
          }
        }
      })
    } else if (options.key && options.throttle) { // we have a key & throttling
      // Deprecate requests per token & throttle requests for the key
      limiter.removeTokens(1, (err, remainingRequests) => {
        setRemaining(options.key, remainingRequests)
        if (getRemaining(options.key) > options.throttle.within) {
          let message = `User with key ${options.key} has ${remainingRequests} left for the time period ${interval}`
          apiLog.writer({ class: 'API', subclass: 'Key Validation', type: 'INFO', context: JSON.stringify(context), message: `${message}, (200)` })
          return callback(null, true, message)
        } else {
          limiter = new RateLimiter(options.throttle.slowDownTo, options.throttle.per)
          let message = `User with key ${options.key} is within the last few allowed requests for the allotted time period. The rate limit has been changed to ${options.throttle.slowDownTo} requests per ${options.throttle.per}`
          apiLog.writer({ class: 'API', subclass: 'Key Validation', type: 'info', context: JSON.stringify(context), message: `${message}, (200)` })
          return callback(null, true, message)
        }
      })
    } else { // you have a key, but no throttling
      limiter.removeTokens(1, (err, remainingRequests) => {
        setRemaining(options.key, remainingRequests)
        if (getRemaining(options.key) < 1) {
          let error = new Error('api/too-many-requests')
          error.message = `User with key ${options.key} has exceeded the number of requests in the time period allotted.`
          error.status = 429 // Too Many Requests
          error.code = 'api/too-many-requests'
          apiLog.writer({ class: 'API', subclass: 'Key Validation', type: 'ERROR', context: JSON.stringify(context), message: `${error.code} : ${error.message}, (${error.status})` })
          return callback(error, false)
        } else { // allow request to go through and set new remaining number for that key
          let message = `User with key ${options.key} has ${remainingRequests} left for the time period ${interval}`
          apiLog.writer({ class: 'API', subclass: 'Key Validation', type: 'ERROR', context: JSON.stringify(context), message: `${message}, (200)` })
          return callback(null, true, message)
        }
      })
    }
  },
  apiKeyRevocation : () => {
    return revokeKey
  },
  keyComber : (request) => { // combs through a request looking for api keys, returns the key if found, otherwise returns null
    let context = {
          from: request.ip,
          method: request.method,
          url: request.url,
          route: request.route,
          browser: request.headers['user-agent'],
          params: () => {
            return request.params || 'no params'
          },
          query: () => {
            return request.query || 'no query string'
          }
        },
        keysFound = [],
        keysLocated = {}
    // search the req.query
    if (request.query) {
      for (let q in request.query) { // for each key in the queries
        if ((q.toLowerCase().includes('key') || q.toLowerCase().startsWith('api')) &&
             request.query[q].length >= 32) {
          keysLocated['query'] = request.query[q]
          keysFound.push(request.query[q])
        }
      }
    }
    if (request.params['api'] || //need to handle upper/lowercase definitions
        request.params['key'] ||
        request.params['apiKey']) {
      let p = request.params['api'] ||
              request.params['key'] ||
              request.params['apiKey']
      keysLocated['params'] = p
      keysFound.push(p)
    }
    // search req.headers
    if (request.headers['authorization'].includes('API') ||
        request.headers['x-api-key']) {
      let k = request.headers['authorization'] || request.headers['x-api-key'],
        words
      words = k.split(" ")
      keysLocated['headers'] = words[(words.length - 1)]
      keysFound.push(words[(words.length - 1)])
    }
    // search req.path
    if (request.path) {
      let allQueries = request.path.split('?'), // [/users, apiKey=1234567&someData=qwerty]
        queries = allQueries[1].split('&'), // [apiKey=2456789, someData=sdfghjk]
        values
      for (let q = 0; q < queries.length; q++) {
        values = queries[q].split('=') // split each params into key and value pairs
        if (values[0].includes('api') || values[0].includes('key')) {
          keysLocated['path'] = values[1]
          keysFound.push(values[1])
        }
      }
    }
    // search cookies
    if (request.cookies) {
      // let's start with unsigned cookies to begin with, then we'll handle signed cookies
      if (Object.keys(request.cookies).includes('apiKey')) {
        keysLocated['cookies'] = request.cookies['apiKey']
        keysFound.push(request.cookies['apiKey'])
      }
      if (Object.keys(request.cookies).includes('key')) {
        keysLocated['cookies'] = request.cookies['key']
        keysFound.push(request.cookies['key'])
      }
      if (Object.keys(request.cookies).includes('api')) {
        keysLocated['cookies'] = request.cookies['api']
        keysFound.push(request.cookies['api'])
      }
    }
    if (keysFound.length > 0) {
      let results = {
            status: 200,
            foundAt: keysLocated,
            allKeys: keysFound,
            message: `Found ${keysFound.length} keys in ${Object.keys(keysLocated)}`
          }
      apiLog.writer({ class: 'API', subclass: 'Key Discovery', type: 'INFO', context: JSON.stringify(context), message: `${results.message}, (${results.status})` })
      return results
    } else {
      let results = {
            status: 404, // Not Found
            foundAt: undefined,
            allKeys: undefined,
            message: 'no keys found'
          }
      apiLog.writer({ class: 'API', subclass: 'Key Discovery', type: 'INFO', context: JSON.stringify(context), message: `${results.message}, (${results.status})` })
      return
    }
  },
  apiDataCheck : () => {

  },
  apiLogger : apiLog
}