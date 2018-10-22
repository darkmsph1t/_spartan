'use strict'
let winston = require('winston')
let p = require('../security.json')
const tsFormat = () => (new Date()).toLocaleTimeString()
let levels = {}
/* ---------------------------------------Logging------------------------------------------------- */
if (p.loggingPolicy.levelsSupported === 'custom') { levels = { levels: p.loggingPolicy.levels } }

var options = {
  file: {
    level: 'info',
    filename: `${ p.loggingPolicy.logCollection.storage }`,
    timestamp: tsFormat,
    handleExceptions: true,
    json: true,
    maxsize: 5242880, // 5MB
    maxFiles: 5,
    colorize: true
  },
  console: {
    level: 'debug',
    handleExceptions: true,
    timestamp: tsFormat,
    json: true,
    colorize: true
  }
}

const logger = winston.createLogger({
  levels: levels.levels,
  transports: [
    new winston.transports.File(options.file),
    new winston.transports.Console(options.console)
  ],
  exitOnError: false // do not exit on handled exceptions
})

module.exports.logger = logger