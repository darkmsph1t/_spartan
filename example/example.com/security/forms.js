'use strict'
const secJson = require('../security.json')

module.exports = (request, response, callback) => {
  if (secJson.formProtection.enabled !== true) {
    let error = new Error('forms/form-protection-disabled')
    error.message = 'Form protection disabled by policy'
    error.status = 400
    callback(error)
    return error
  }
  if (secJson.formProtection.config.methodOverride === false && (request.method !== 'GET' || request.method !== 'POST')) {
    let error = new Error('forms/method-override-forbidden')
    error.message = 'Method override disabled by policy'
    error.status = 400
    callback(error)
    return error
  }
  let autocomplete = 'off'
  if (secJson.formProtection.config.autocompleteAllowed === true) {
    autocomplete = 'on'
  }
  let csrf = ''
  if (secJson.sessionPolicy.config.csrfSettings.allowHiddenToken === true) {
    csrf = request.csrfToken()
  }
  return {
    autocomplete: autocomplete,
    method: request.method,
    _csrf: csrf
  }
}
