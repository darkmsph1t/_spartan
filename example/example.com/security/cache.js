'use strict'
const secJson = require('../security.json')
const redis = require('redis')
// const PORT = require('./secrets').fetchSecret('CACHE_PORT') || 9000
const REDIS_PORT = require('./secrets').fetchSecret('REDIS_PORT')
const client = redis.createClient(REDIS_PORT)

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

module.exports = () => {
  // check to see if cache protection is enabled
  if (secJson.securityHeaders.caching.enabled === false) {
    let error = new Error('cache/cache-policy-disabled')
    error.message = 'Caching is not enabled for this application'
    return error
  } else {
    return {
      cacheHeaders: setCacheHeaders(),
      setCache: (route, fetchedThing, callback) => {
        if (secJson.caching.routeOverload === false && route !== undefined) {
          let error = new Error('cache/route-overload-disabled')
          error.message = `Sorry! Route overload has been disabled for ${route}`
          callback(error, null)
        } else {
          try {
            client.setex(route, secJson.caching.ttl, fetchedThing)
            let data = 'success'
            callback(null, data)
          } catch (err) {
            callback(err, null)
          }
        }
      },
      getCache: async (route, fetchedThing, callback) => {
        client.get(route, function (err, data) {
          if (err) {
            err.code = '(\'cache/could-not-fetch-data\')'
            err.message = `Could not fetch data for ${route}`
            callback(err, null)
          }
          if (data !== null) {
            callback(null, data)
          } else {
            let error = new Error('cache/ttl-expired')
            error.message = 'Time to live for this data has expired'
            callback(error, undefined)
          }
        })
      }
    }
  }
}
