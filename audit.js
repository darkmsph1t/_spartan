'use strict'
var fs = require('fs')
var d = new Date()
var options = {
//          weekday: 'long',
  year: 'numeric',
  month: 'short',
  day: 'numeric',
  hour: '2-digit',
  minute: '2-digit'
}
var pathToAudits = './auditLog.json'
var pathToErrors = './errors.json'
var errorObject = {}
var r = require('./policy.js')
var a
var oldId
class Audit {
  constructor () {
    this.created = undefined
    this.modified = undefined
    this.deleted = undefined
    this.overwriten = undefined
  }
  setCreated () {
    this.created = `${d.toLocaleString('en-us', options)} by some person`
    return this.created
  }
  setModified () {
    this.modified = `${d.toLocaleString('en-us', options)} by some person`
  }
  setDeleted () {
    this.deleted = `${d.toLocaleString('en-us', options)} by some person`
  }
  setOverwritten () {
    this.overwriten = `${d.toLocaleString('en-us', options)} by some person`
  }
}
function isEmptyObject (obj) {
  return !Object.keys(obj).length
}
async function writeToAudit (policyId, action) {
  try {
    a = r.read(pathToAudits)
    if (isEmptyObject(a)) {
      var audit = new Audit()
      audit.setCreated()
      a[policyId] = audit
    } else {
      for (var i in a) {
        if (i === policyId) {
          a[i][action] = `${d.toLocaleString('en-us', options)} by some person`
        } else {
          var allIds = Object.keys(a)
          oldId = allIds[allIds.length - 1]
          if (!a[oldId]['deleted']) {
            a[oldId]['overwriten'] = `${d.toLocaleString('en-us', options)} by some person`
          }
          audit = new Audit()
          audit.setCreated()
          a[policyId] = audit
        }
      }
    }
    var record = fs.createWriteStream(pathToAudits, { flag: 'wx' })
    record.write('{\n' + JSON.stringify(a, null, ' ') + '\n}')
    record.close()
  } catch (e) {
    writeToError(policyId, action, e)
  }
}

function writeToError (policyId, action, error) {
  try {
    errorObject[policyId] = { [action]: `${error} occured on ${d.toLocaleString('en-us', options)} while attempting to ${action} the policy` }
    // console.log(errorObject);
    var err = fs.createWriteStream(pathToErrors, { 'flags': 'a' })
    err.write(JSON.stringify(errorObject, null, ' '))
    err.close()
  } catch (e) {
    console.error(e)
  }
}

module.exports.writeToAudit = writeToAudit
module.exports.writeToError = writeToError
