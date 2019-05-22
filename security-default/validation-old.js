'use strict'
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
              let error = `${ requestHeaders[header] } is invalid in header ${ header } `
              error.status = 401
              callback(error)
            }
          } else {
            // otherwise, report an error to the call back function that a whitelist for THAT header could not be found
            let error = `Unable to check ${ header } 's whitelist to validate ${requestHeaders[header]}`
    error.status = 500
    callback(error, requestHeaders[header])
  }
        } else {
  // if the header does not require a whitelist, report a MESSAGE in the callback that the header does not require a whitelist and its value was not validated
  let message = { [header]: `Header ${header} does not require validation` }
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
    let message = `These are the currently supported ciphers: ${tls.getCiphers()}`
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
          let err = new Error(`Invalid input type. Expected ${rules[rule].type}. Instead found ${(typeof obj[object])}`)
          return err
        } else {
          let error = new Error(`Invalid input type. Expected ${rules[rule].type}. Instead found ${(typeof obj[object])}`)
          return error
        }
      }
    }
  }
  if (!validate.isObj(obj) || !validate.isObj(rules)) {
    const err = new Error(`Invalid Type Found. Cannot validate ${obj} against ${rules}`)
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