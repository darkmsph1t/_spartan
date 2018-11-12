'use strict'
let winston = require('winston')
let p = require('../security.json')
let moment = require('moment')
let levels = {}
/* ---------------------------------------Logging------------------------------------------------- */
var options = {
  file: {
    level: 'info',
    filename: `${p.loggingPolicy.logCollection.storage}`,
    timestamp: moment().format('dddd, MMMM Do YYYY, h:mm:ss a'),
    handleExceptions: true,
    json: true,
    maxsize: 5242880, // 5MB
    maxFiles: 5,
    colorize: true
  },
  console: {
    level: 'debug',
    handleExceptions: true,
    timestamp: moment().format('dddd, MMMM Do YYYY, h:mm:ss a'),
    json: true,
    colorize: true
  }
}

// What parts of security.json do I need to pull in in order to make smart logging decisions? --require research
// how do I apply event type (security, error, system) labels && severity to each log event? --requires research

module.exports = () => {
  if (p.loggingPolicy.levelsSupported === 'custom') {
    levels = { levels: p.loggingPolicy.levels }
  }
  if (p.loggingPolicy.enabled === false) {
    let error = new Error('logging/logging-policy-disabled')
    error.message = 'Logging disabled by policy'
    return error
  }
  return winston.createLogger({
    levels: levels.levels,
    transports: [
      new winston.transports.File(options.file),
      new winston.transports.Console(options.console)
    ],
    exitOnError: false // do not exit on handled exceptions
  })
}
