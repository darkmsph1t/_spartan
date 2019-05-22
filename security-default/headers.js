'use strict'
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
      // hashedSites[keys] = { [keys]: `sha256 - ${ hasher(keys[site]) } ` }
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
      if (csp.reportOnly !== true) {
        let sri = []
        if (csp.requireSriFor.scripts) {
          sri.push('script')
        }
        if (csp.requireSriFor.styles) {
          sri.push('style')
        }
        d['requireSriFor'] = sri
      }
      if (csp.sandbox.enable === true) {
        let sandbox = []
        for (let l in csp.sandbox) {
          if (csp.sandbox[l] === true) {
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
    if (options.cdp) { // cdp == cross domain policies
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
    if (!options.hidePower) {
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
    if (!options.sts) {
      headers.hsts = false
    } else if (options.sts.usePolicy === true && secJson.securityHeaders.config.strictTransportSecurity.enabled) {
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