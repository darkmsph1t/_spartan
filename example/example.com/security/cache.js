'use strict'
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
      let error = new Error(`Sorry! Route overload has been disabled for ${route}`)
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
