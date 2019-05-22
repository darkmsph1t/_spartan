'use strict'
let secJson = require('../security.json')
const mongoose = require('mongoose')
const dbConnect = require('./secrets').fetchSecret('DB_CONNECTION')

module.exports = function dbSec () {
  if (!secJson.dbSecurityPolicy.enabled) {
    throw new Error(`Could not establish connection to database.Database security policy is: ${ secJson.dbsecurityPolicy.enabled }`)
  }
  // create the connection
  mongoose.connect(dbConnect)
  let db = mongoose.connection
  db.on('error', console.error.bind(console, 'connection error:'))
  let schemaObject = {}
  let setSchema = function (name, schema) {
    schemaObject[name] = mongoose.model(name, schema)
    return schemaObject[name]
  }

  let createRecord = function (name, data, callback) {
    let Model = name
    Model.create(data, function (error, record) {
      if (error) {
        return callback(error)
      } else {
        return callback(null, record)
      }
    })
  }
  return {
    setSchema: setSchema,
    createRecord: createRecord
  }
}