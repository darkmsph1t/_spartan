'use strict'
let moment = require('moment')
let secJson = require('../security.json')
const mongoose = require('mongoose')
const dbConnect = require('./secrets').fetchSecret('DB_CONNECTION')

module.exports = (todo) => {
  if (!secJson.dbSecurityPolicy.enabled) {
    let code = 'database/policy-not-enabled'
    let error = new Error(code)
    error.message = `Could not establish connection to database. Database security policy is: ${secJson.dbsecurityPolicy.enabled}`
    return { code: error.code, message: error.message }
  }
  if (todo === 'init') {
    return () => {
      // create the connection
      mongoose.connect(dbConnect)
      let db = mongoose.connection
      db.on('error', (err) => {
        if (err) {
          console.error.bind(console, 'connection error:')
          let error = new Error('database/no-connection')
          error.message = `There was a problem connecting to the database`
          return { code: error.code, message: error.message }
        }
      })
      db.once('open', () => {
        return `Connected to database at ${moment().format('MMMM Do YYYY, h:mm:ss a')}`
      })
    }
  } else if (todo === 'setSchema') {
    let schemaObject = {}
    return (name, schema) => {
      schemaObject[name] = mongoose.model(name, schema)
      return schemaObject[name]
    }
  } else if (todo === 'create') {
    return (name, data, callback) => {
      let Model = name
      Model.create(data, function (error, record) {
        if (error) {
          return callback(error)
        } else {
          return callback(null, record)
        }
      })
    }
  } else {
    let error = new Error('database/bad-request')
    error.message = `A bad request was presented to the database ${todo}`
  }
}
