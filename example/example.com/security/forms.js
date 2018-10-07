'use strict'
const secJson = require('../security.json')

class Form {
  constructor (method, fields, action, submit) {
    this.method = method
    this.fields = fields
    this.action = action
    this.submit = submit
  }
  formBuilder (field) {
    let element = ``
    for (let key in field) {
      if (key !== 'validation') {
        element += `<label for="id_${key}">${field[key].label}</label>
                    <input type="${field[key].type}" name="${key}" id="id_${key}" /><br>`
      }
    }
    // element = element + `</div>`
    return element
  }
}

module.exports = function formSec (request, response, callback) {
  function generateForm (rules) {
    if (rules.method && rules.fields && rules.action && rules.submit) {
      let form = new Form(rules.method, rules.fields, rules.action, rules.submit)
      let html = ``
      if (secJson.formProtection.config.autocompleteAllowed === true) {
        html = `<form action="${form.action}" method="${form.method}" autocomplete="on"`
      } else {
        html = `<form action="${rules.action}" method=${rules.method} autocomplete="off">`
      }
      if (rules.fields.validation === { required: true }) {
        html += `<div class="field required">`
      } else {
        html += `<div class="field">`
      }
      let fields = rules
      for (let f in fields) {
        if (f !== 'method' && f !== 'action' && f !== 'submit') {
          html = html + form.formBuilder(fields[f])
        }
      }
      // return `${html}<input type="submit" value=${rules.submit}><input type="hidden" name="_csrf" value="${request.csrfToken()}</form>`
      return `${html}<input type="submit" value=${rules.submit}><input type="hidden" name="_csrf" value="csrftoken"</form>`
    } else {
      let error = new Error(`Required components missing`)
      return error
    }
  }

  if (secJson.formProtection.enabled !== true) {
    let error = new Error('Form protection disabled by policy')
    error.status = 400
    return error
  } else if (secJson.formProtection.config.methodOverride === false && (request.method !== 'GET' || request.method !== 'POST')) {
    let error = new Error('Method override disabled by policy')
    error.status = 400
    return error
  } else {
  }
  return {
    generateForm: generateForm
  }
}
