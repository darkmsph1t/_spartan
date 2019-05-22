'use strict'
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
}