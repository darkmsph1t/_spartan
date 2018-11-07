'use strict'
const secJson = require('../security.json')
// const validInput = require('./validation').validInput()
const fs = require('fs')
const https = require('https')
const http = require('http')
const cert = require('./secrets').fetchSecret('CERTIFICATE')
const key = require('./secrets').fetchSecret('PRIV_KEY')
// const ca = require('./secrets').fetchSecret('CERT_AUTH')
const { constants } = require('crypto')
const port = require('./secrets').fetchSecret('PORT') || 8080

// this module is concerned with the establishment and maintenance of https connections to the server && provides redirect for any attempted connections to non-secure port(s)

/* NOTE: this module assumes you have already created certificates required. Be sure to add their absolute paths to your .env file as CERTIFICATE and PEM respectively */

module.exports = {
  secureServer: (app, callback) => {
    if (secJson.connectionPolicy.enabled === false) {
      let error = new Error('https/connection-policy-not-enabled')
      error.message = `Connection policy is currently set to ${secJson.connectionPolicy.enabled}.`
      callback(error)
      return error
    }
    // handle file not found errors
    if (fs.readFileSync(cert) instanceof Error) { // NOENT error if the file path is invalid
      let error = new Error('https/invalid-certificate-path')
      error.message = 'no certificate at provided location'
      callback(error)
      return error
    }
    if (fs.readFileSync(key) instanceof Error) {
      let error = new Error('https/invalid-key-path')
      error.message = 'no private key at provided location'
      callback(error)
      return error
    }
    const options = {
      secureOptions: constants.SSL_OP_NO_TLSv1, // prevents use of TLSv1 (have to use TLS1.1 or better)
      key: fs.readFileSync(key),
      cert: fs.readFileSync(cert),
      // ca: fs.readFileSync(ca), // again, you don't need this if you're not rolling your own CA
      // ciphers: ciphers => only use this if you're not using the default ciphers
      honorCipherOrder: true
    }
    if (app) {
      return https.createServer(options, app).listen(port)
    } else {
      callback = function (request, response) {
        console.log(`I'm listening on port ${request.port}`)
        response.send('Hello')
      }
      return https.createServer(options, callback).listen(port)
    }
  },
  redirectHttp: (app, callback) => {
    if (secJson.connectionPolicy.redirectSecure) {
      if (callback) {
        callback()
      }
      if (app) {
        return http.createServer(app, function (request, response) {
          response.writeHead(307, { Location: `https://${secJson.hostname}:${port}${request.url}` })
          response.end()
        }).listen(3000)
      } else {
        return http.createServer(function (request, response) {
          response.writeHead(307, { Location: `https://${secJson.hostname}:${port}${request.url}` })
          response.end()
        }).listen(3000) // this is the "insecure" port your application will listen on. Change this if you want to use a different port
      }
    } else {
      let err = new Error('Redirection not configured by security policy')
      return err
    }
  }
}
