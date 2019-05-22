'use strict'
const cors = require('cors')
const secJson = require('../security.json')

var backslash = "'\\.'"
const subdomainTransform = function (whitelistElm) {
  if (whitelistElm.includes('*')) {
    whitelistElm = whitelistElm.substr(1)
    whitelistElm = whitelistElm.split('.').join(backslash)
    whitelistElm = `/${whitelistElm}$/`
    return whitelistElm
  } else {
    let error = new Error('cors/whitelist-subdomain-transform')
    error.message = 'There was a problem transforming whitelist subdomains'
    return error
  }
}
/* Here we need to distinguish between non-senstive and sensitive operations; anyone can make a GET request; otherwise, the more sensitive the operation (PUT, POST, PATCH), the more stringent the whitelist. As an example, mysite.foo.bar should be able to make a GET request...I don't need to whitelist that out because it's a non-sensitive operation (with some conditions, like credentials) however we DO need to put HTTPS://mysite.foo.bar:8080 on our whitelist if we're going to allow it to make changes to our server. FOR THAT REASON, I would HIGHLY recommend NOT allowing ALL subdomains of a host on your whitelist, but rather a few, very specific routes on a host */

module.exports = () => {
  if (secJson.resourceSharingPolicy.corsSettings.enabled === false) {
    let error = new Error('cors/disabled-by-policy')
    error.message = 'CORS disabled by policy. Same-origin policy remains in effect'
    return error
  }
  let w = secJson.resourceSharingPolicy.corsSettings.config.whitelist
  // if (secJson.resourceSharingPolicy.corsSettings.enabled === true && w === []) {
  //   // Overly permissive whitelist => Access-Control-Allow-Origin *, for all methods BAD BAD BAD!
  //   w = [`https://${secJson.hostname}:8080`]
  // }
  // Now let's parse the whitelist looking for subdomain declarations
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
          let error = new Error('cors/origin-not-allowed')
          error.message = 'The origin is not allowed'
          cb(error, null)
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
