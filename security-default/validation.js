'use strict'
let fileUpload = require('express-fileupload'),
    readChunk = require('read-chunk'),
    fileType = require('file-type'),
    fs = require('fs'),
    validate  = require('validate.js'),
    uaParser = require('ua-parser-js'),
    whitelists = require('./security/.whitelists.json'),
    maxFileSize,
   { LogWriter } = require('./logger'),
   valLog = new LogWriter({ console : false, file: true })

const check = (info) => {
  let errorsArray = []
  for (let i = 0; i < info.fields.length; i++) {
    if (typeof info.fields[i] !== 'string') {
      let error = new Error('validation/invalid-rule-set')
      error.code = 'validation/invalid-rule-set'
      error.status = 400
      error.message = `The fields must be of type: string. Found field of type ${typeof info.fields[i]}`
      errorsArray.push(error)
    }
  }
}  
const checkType = (typeRule, data) => {
  if (typeRule === String) {
    return validate.isString(data)
  } else if (typeRule === 'Integer') {
    return validate.isInteger(data)
  } else if (typeRule === Array) {
    return validate.isArray(data)
  } else if (typeRule === Boolean) {
    return validate.isBoolean(data)
  } else if (typeRule === Date) {
    return validate.isDate(data)
  } else if (typeRule === Function) {
    return validate.isFunction(data)
  } else if (typeRule === Promise) {
    return validate.isPromise(data)
  } else if (typeRule === Object) {
    return validate.isObject(data)
  } else if (typeRule === Number) {
    return validate.isNumber(data)
  } else if (typeRule === 'Hash') {
    return validate.isHash(data)
  } else if (typeRule.contains('DOM')) {
    return validate.isDomElement(data)
  } else {
    let error = new Error('validation/unknown-type')
    error.status = 400
    error.code = 'validation/unknown-type'
    error.message `The data type provided could not be validated against the given rule set`
    return error
  }
}
const checkPresence = (presenceRule, data) => { //presence rule = constraints object
  if (validate.isEmpty(data) && (presenceRule.allowEmpty === false || presenceRule.allowEmpty === undefined)) {
    return 'Value was empty, but is required'
  } else {
    return validate.single(data, presenceRule)
  }
}
const checkFormat = (formatRule, data) => {
  if (data === undefined) {
    return undefined
  } else {
    return validate.single(data, formatRule)
  }
}
const checkLength = (lengthRule, data) => {
  if (data === undefined) {
    return undefined
  } else {
    return validate.single(data, lengthRule)
  }
}
const checkDate = (dateRule, data) => {
  return validate.single(data, dateRule)
}
const checkEquality = (equalityRule, data) => {
  return validate.single(data, equalityRule)
}
const checkExclusion = (exclusionRule, data) => {
  return validate.single(data, exclusionRule)
}
const checkInclusion = (inclusionRule, data) => {
  return validate.single(data, inclusionRule)
}
const checkUrls = (urlRules, data) => {
  return validate.single(data, urlRules)
}
const checkNumericality = (numberRules, data) => {
  return validate.single(data, numberRules)
}
const magicNumber = (file) => {
  let fileData = fileType(readChunk.sync(file.path, 0, fileType.minimumBytes))
  return fileData
}
module.exports = {
  checkUploads : (request, uploadInfo, callback) => {
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
    // check to see if files exist
    if (!request.files) {
      let error = new Error('validation/error-on-upload')
      error.code = 'validation/error-on-upload'
      error.message = 'An error occurred during the upload process'
      error.status = 404 // not found
      valLog.writer({ class: 'VALIDATION', subclass: 'UPLOAD Validation', type: 'ERROR', context: JSON.stringify(context), message: `${error.code} : ${error.message}, (${error.status})` })
      return callback(error, false)
    }

    let fileList = Object.keys(request.files)
    //check file size
    if(request.files[fileList[0]].size >= maxFileSize) {
      let error = new Error('validation/file-too-big')
      error.message = `The file must be smaller than ${maxFileSize}B`
      error.status = 400 // bad request
      error.code = 'validation/file-too-big'
      valLog.writer({ class: 'VALIDATION', subclass: 'UPLOAD Validation', type: 'ERROR', context: JSON.stringify(context), message: `${error.code} : ${error.message}, (${error.status})` })
      return callback(error, false)
    }
    
    // check file type
    let fType = (request.files[fileList[0]].name).split('.').pop().toLowerCase() // need to fix this
    if (!uploadInfo.acceptableTypes.includes(fType) && !uploadInfo.acceptableTypes.includes('*')) {
      let error = new Error('validation/invalid-file-type')
      error.message = `The file type ${fType} is prohibited`
      error.status = 400 // Bad Request
      error.code = 'validation/invalid-file-type'
      valLog.writer({ class: 'VALIDATION', subclass: 'UPLOAD Validation', type: 'ERROR', context: JSON.stringify(context), message: `${error.code} : ${error.message}, (${error.status})` })
      return callback(error, false)
    }
    // finally, upload the file
    let counter = 0
    for (let i = 0; i < fileList.length; i++) {
      if(request.files[fileList[i]].mv) {
        request.files[fileList[i]].mv(`${uploadInfo.saveLocation}${request.files[fileList[i]].name}`, (err) => {
          if (err) { counter ++ }
        })
      }
    }
    if (counter > 0) {
      let err = new Error('validation/problem-uploading-file')
      err.message = 'There was a problem uploading files'
      err.status = 400 // Bad Request
      err.code = 'validation/problem-uploading-file'
      valLog.writer({ class: 'VALIDATION', subclass: 'UPLOAD Validation', type: 'ERROR', context: JSON.stringify(context), message: `${error.code} : ${error.message}, (${error.status})` })
      return callback(err, false)
    } else {
      valLog.writer({ class: 'VALIDATION', subclass: 'UPLOAD Validation', type: 'INFO', context: JSON.stringify(context), message: `File ${fileList} was uploaded without incident (200)` })
      return callback(null, true)
    }
  },
  /**    
   *  @name checkBrowser
   *  @description checks whether the request is coming in from an allowed browser (user agent); can either be used on each route (app.use or on individual routes); two methods included => enforce : only allows ua strings on the existing whitelist; monitor : builds the ua library; suggested use : monitor for a predetermined amount of time (like 3 weeks, then switch to enforce mode); TODO: add a database config to monitor mode
   */
  checkBrowser : (req, options, callback) => {
    let context = {
        from: req.ip,
        method: req.method,
        url: req.url,
        route: req.route,
        browser: req.headers['user-agent'],
        params: () => {
          return req.params || 'no params'
        },
        query: () => {
          return req.query || 'no query string'
        }
    }
    if (options === 'enforce') {
      if (!whitelists['user-agent'].includes(req.headers['user-agent'])) {
        let error = new Error('validation/invalid-user-agent')
        error.status = 400
        error.code = 'validation/invalid-user-agent'
        error.message = `The user agent ${req.headers['user-agent']} is prohibited`
        valLog.writer({ class: 'VALIDATION', subclass: 'BROWSER Validation', type: 'ERROR', context: JSON.stringify(context), message: `${error.code} : ${error.message}, (${error.status})` })
        return callback(error, false)
      } else {
        valLog.writer({ class: 'VALIDATION', subclass: 'BROWSER Validation', type: 'INFO', context: JSON.stringify(context), message: `Found valid user agent, (200)` })
        return callback(null, true)
      }
    } else if (options === 'monitor'){
      let message
      if (!whitelists['user-agent'].includes(req.headers['user-agent'])) {
        whitelists['user-agent'].push(uaParser(req.headers['user-agent']).ua)
        message = `Added ${req.headers['user-agent']} to the whitelist`
      } else {
        message = `${req.headers['user-agent']} was already on the acceptable user-agents list`
      }
      fs.writeFileSync('./security/.whitelists.json', JSON.stringify(whitelists))
      valLog.writer({ class: 'VALIDATION', subclass: 'BROWSER Validation', type: 'INFO', context: JSON.stringify(context), message: `${message}, (200)` })
      return callback(null, true, message)
    } else {
      let error = new Error('validation/browser-validation-error')
      error.code = 'validation/browser-validation-error'
      error.message = 'Could not validate browser'
      error.status = 400
      valLog.writer({ class: 'VALIDATION', subclass: 'BROWSER Validation', type: 'ERROR', context: JSON.stringify(context), message: `${error.code} : ${error.message}, (${error.status})` })
      return callback(error, false)
    }
  },
  checkConnection : (req, rules, callback) => {
    // ([request | url], { allowedSchemes: String Array }, callback)
    // TODO: CHECK CERTIFICATE VALIDITY
    let context = {
      from: req.ip,
      method: req.method,
      url: req.url,
      route: req.route,
      browser: req.headers['user-agent'],
      params: () => {
        return req.params || 'no params'
      },
      query: () => {
        return req.query || 'no query string'
      }
    }
    if (req.protocol.includes(':')) {
       req.protocol = (req.protocol).slice(0, -1)
    }
    try {
      if (rules.allowedSchemes.includes('*')) {
        valLog.writer({ class: 'VALIDATION', subclass: 'CONNECTION Validation', type: 'INFO', context: JSON.stringify(context), message: `All schemes are allowed by rule definition` })
        return callback(null, true)
      } else if (typeof req === 'URL') {
        if (validate({website : req}, {website : {url : { schemes : rules.allowedSchemes}}}) !== undefined) {
          let err = new Error('validation/scheme-not-allowed')
          err.code = 'validation/scheme-not-allowed'
          err.status = 400
          err.message = 'The scheme provided is not allowed'
          valLog.writer({ class: 'VALIDATION', subclass: 'CONNECTION Validation', type: 'ERROR', context: JSON.stringify(context), message: `${err.code} : ${err.message}, (${err.status})` })
          return callback(err, false)
        }
      } else if(rules.allowedSchemes.includes(req.protocol)) {
        valLog.writer({ class: 'VALIDATION', subclass: 'CONNECTION Validation', type: 'INFO', context: JSON.stringify(context), message: `${req.protocol} is allowed` })
        return callback(null, true)
      } else {
        let error = new Error('validation/invalid-protocol-scheme')
        error.status = 400
        error.code = 'validation/invalid-protocol-scheme'
        error.message = `The scheme provided, ${req.protocol}, is prohibited, only ${rules.allowedSchemes} is allowed`
        valLog.writer({ class: 'VALIDATION', subclass: 'CONNECTION Validation', type: 'ERROR', context: JSON.stringify(context), message: `${error.code} : ${error.message}, (${error.status})` })
        return callback(error, false)
      }
    } catch (e) {
      valLog.writer({ class: 'VALIDATION', subclass: 'CONNECTION Validation', type: 'ERROR', context: JSON.stringify(context), message: `An error occurred while trying to validate the connection type. ${e.message}` })
      return callback(e, false)
    }
  },
  checkHeaders : (req, whitelistOverride, callback) => {
    let context = {
      from: req.ip,
      method: req.method,
      url: req.url,
      route: req.route,
      browser: req.headers['user-agent'],
      params: () => {
        return req.params || 'no params'
      },
      query: () => {
        return req.query || 'no query string'
      }
    }
    let providedHeaders = Object.keys(req["headers"])
    if (whitelistOverride === null || whitelistOverride === undefined) {
      let requiredHeaders = Object.keys(whitelists)
      if (requiredHeaders.length < providedHeaders.length) {
        let err = new Error('validation/too-many-headers')
        err.message = `The request provided more headers than expected`
        err.status = 400 // Bad request
        err.code = 'validation/too-many-headers'
        valLog.writer({ class: 'VALIDATION', subclass: 'HEADER Validation', type: 'ERROR', context: JSON.stringify(context), message: `${err.code} : ${err.message}, (${err.status})` })
        return callback(err, false)
      } else if (requiredHeaders.length > providedHeaders.length) {
        let err = new Error('validation/missing-headers')
        err.message = `The request is missing headers`
        err.status = 400 // Bad request
        err.code = 'validation/missing-headers'
        valLog.writer({ class: 'VALIDATION', subclass: 'HEADER Validation', type: 'ERROR', context: JSON.stringify(context), message: `${err.code} : ${err.message}, (${err.status})` })
        return callback(err, false)
      } else {
        for (let p = 0; p < providedHeaders.length; p++) {
          if (!requiredHeaders.includes(providedHeaders[p])) {
            // checks to see if provided header is in the list of allowed headers
            let error = new Error('validation/unauthorized-header')
            error.message = `${providedHeaders[p]} is not allowed`
            error.status = 400 // Bad request
            error.code = 'validation/unauthorized-header'
            valLog.writer({ class: 'VALIDATION', subclass: 'HEADER Validation', type: 'ERROR', context: JSON.stringify(context), message: `${error.code} : ${error.message}, (${error.status})` })
            return callback(error, false)
          }
        }
        valLog.writer({ class: 'VALIDATION', subclass: 'HEADER Validation', type: 'SUCCESS', context: JSON.stringify(context), message: `Header Check Passed, (200)` })
        return callback(null, true)
      }
      // need to actually check the header values
    } else if (whitelistOverride) {
      let overrideHeaders = Object.keys(whitelistOverride)
      if (overrideHeaders.length === 0 || typeof whitelistOverride !== 'object') {
        let error = new Error('validation/type-mismatch')
        error.message = 'The whitelist must be an object with at least one key-value pair'
        error.code = 'validation/type-mismatch'
        error.status = 400
        valLog.writer({ class: 'VALIDATION', subclass: 'HEADER Validation', type: 'ERROR', context: JSON.stringify(context), message: `${error.code} : ${error.message}, (${error.status})` })
        return callback(error, false)
      }
      if (overrideHeaders.length < providedHeaders.length) {
        let error = new Error('validation/too-many-headers')
        error.message = 'The request provided more headers than expected'
        error.status = 400 // bad request
        error.code = 'validation/too-many-headers'
        valLog.writer({ class: 'VALIDATION', subclass: 'HEADER Validation', type: 'ERROR', context: JSON.stringify(context), message: `${error.code} : ${error.message}, (${error.status})` })
        return callback(error, false)
      } else if (overrideHeaders.length > providedHeaders.length) {
        let error = new Error('validation/missing-headers')
        error.message = 'The request is missing required headers'
        error.status = 400 // Bad request
        error.code = 'validation/missing-headers'
        valLog.writer({ class: 'VALIDATION', subclass: 'HEADER Validation', type: 'ERROR', context: JSON.stringify(context), message: `${error.code} : ${error.message}, (${error.status})` })
        return callback (error, false)
      } else {
        let error = new Error('validation/prohibited-headers')
        error.status = 400 // Bad request
        error.code = 'validation/prohibited-headers'
        for (let q = 0; q < providedHeaders.length; q++) {
          if (!overrideHeaders.includes(providedHeaders[q])) {
            error.message = `Header ${providedHeaders[q]} is not allowed`
            valLog.writer({ class: 'VALIDATION', subclass: 'HEADER Validation', type: 'ERROR', context: JSON.stringify(context), message: `${error.code} : ${error.message}, (${error.status})` })
            return callback(error, false)
          }
        }
        valLog.writer({ class: 'VALIDATION', subclass: 'HEADER Validation', type: 'ERROR', context: JSON.stringify(context), message: `Header values are within expected parameters, (200)` })
        return callback(null, true)
      }
    } else {
      valLog.writer({ class: 'VALIDATION', subclass: 'HEADER Validation', type: 'INFO', context: JSON.stringify(context), message: `Header values are within expected parameters, (200)` })
      return callback(null, true)
    }
  },
  checkData : (req, data, ruleset, callback) => {
    let context = {
      from: req.ip,
      method: req.method,
      url: req.url,
      route: req.route,
      browser: req.headers['user-agent'],
      params: () => {
        return req.params || 'no params'
      },
      query: () => {
        return req.query || 'no query string'
      }
    }
    let d = Object.keys(data),
        r = Object.keys(ruleset),
        e,
        counter = 0

    for (let i = 0; i < Object.keys(data).length; i++) {
      e = new Error('validation/data-ruleset-mismatch')
      e.message = 'the data cannot be matched to the provided ruleset'
      e.status = 400 // bad request
      e.code = 'validation/data-ruleset-mismatch'
      if (!r.includes(d[i])){
        counter++
      }
    }
    if (counter > 0) {
      valLog.writer({ class: 'VALIDATION', subclass: 'DATA Validation', type: 'ERROR', context: JSON.stringify(context), message: `${e.code} : ${e.message}, (${e.status})` })
      return callback(e, false, null)
    }
    if (typeof data !== 'object' || Object.keys(data).length < 1) {
      let error = new Error('validation/invalid-data-object-format')
      error.message = 'Data must be a non-empty object'
      error.code = 'validation/invalid-data-object-format'
      error.status = 400 // Bad Request
      valLog.writer({ class: 'VALIDATION', subclass: 'DATA Validation', type: 'ERROR', context: JSON.stringify(context), message: `${error.code} : ${error.message}, (${error.status})` })
      return callback(error, false, null)
    } else if (typeof ruleset !== 'object' || Object.keys(ruleset).length < 1) {
      let error = new Error('validation/invalid-ruleset-object-format')
      error.message = 'Ruleset must be a non-empty object'
      error.code = 'validation/invalid-ruleset-object-format'
      error.status = 400 // Bad Request
      valLog.writer({ class: 'VALIDATION', subclass: 'DATA Validation', type: 'ERROR', context: JSON.stringify(context), message: `${error.code} : ${error.message}, (${error.status})` })
      return callback(error, false, null)
    } else {
      let dataErrors = validate(data, ruleset)
      if (dataErrors) {
        let error = new Error('validation/validation-errors-found')
        error.message = `The following validation errors occurred: ${JSON.stringify(dataErrors)}`
        error.status = 400
        error.code = 'validation/validation-errors-found'
        valLog.writer({ class: 'VALIDATION', subclass: 'DATA Validation', type: 'ERROR', context: JSON.stringify(context), message: `${error.code} : ${error.message}, (${error.status})` })
        return callback(error, false, dataErrors)
      } else {
        valLog.writer({ class: 'VALIDATION', subclass: 'DATA Validation', type: 'SUCCESS', context: JSON.stringify(context), message: `No Data Errors Discovered` })
        return callback(null, true, null)
      }
    }
  },
  upload : (options) => {
    return fileUpload(options)
  }, 
  overflow: (request, res, callback) => {
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
    let err = new Error('validation/file-too-big')
    err.message = 'the file is too big'
    err.status = 400 // bad request
    err.code = 'validation/file-too-big'
    valLog.writer({ class: 'VALIDATION', subclass: 'UPLOAD Validation', type: 'ERROR', context: JSON.stringify(context), message: `${err.code} : ${err.message}, (${err.status})` })
    return callback(err, false)
  },
  validationLogger : valLog
}