'use strict'
require('dotenv').config()
const secJson = require('../security.json')
// const validInput = require('./validation').validInput()
const fs = require('fs')
const https = require('https')
const http = require('http')
const cert = require('./secrets').fetchSecret('CERTIFICATE')
const key = require('./secrets').fetchSecret('PRIV_KEY')
// const ca = require('./secrets').fetchSecret('CERT_AUTH')
const { constants } = require('crypto')
// const ciphers => use default node ciphers for now. See node docs if you want to change this
const port = require('./secrets').fetchSecret('PORT') || 8080

// this module is concerned with the establishment and maintenance of https connections to the server && provides redirect for any attempted connections to non-secure port(s)

/* NOTE: this module assumes you have already created certificates required. Be sure to add their absolute paths to your .env file as CERTIFICATE and PEM respectively */
function cb (err, c, p) {
  if (c instanceof Error) return console.log(`${ err }: ${ c } `)
  else return console.log(`${ err }: ${ p } `)
}
const secureServer = function (app, callback) {
  if (cert instanceof Error || key instanceof Error) {
    const error = new Error(`Could not create a secure server`)
    cb(error, cert, key)
  }
  if (callback && typeof callback === 'function') {
    callback()
  }
  const options = {
    secureOptions: constants.SSL_OP_NO_TLSv1,
    key: fs.readFileSync(key),
    cert: fs.readFileSync(cert),
    // ca: fs.readFileSync(ca),
    // ciphers: ciphers => using default node ciphers
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
}
const redirectHttp = (app, callback) => {
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
      }).listen(3000)
    }
  } else {
    let err = new Error('Redirection not configured by security policy')
    return err
  }
}
// future release =>
/*
const certPin(cert) {
  function sha256(s) {
  return crypto.createHash('sha256').update(s).digest('base64');
}
const options = {
  hostname: 'github.com',
  port: 443,
  path: '/',
  method: 'GET',
  checkServerIdentity: function(host, cert) {
    // Make sure the certificate is issued to the host we are connected to
    const err = tls.checkServerIdentity(host, cert);
    if (err) {
      return err;
    }

    // Pin the public key, similar to HPKP pin-sha25 pinning
    const pubkey256 = 'pL1+qb9HTMRZJmuC/bB/ZI9d302BYrrqiVuRyW+DGrU=';
    if (sha256(cert.pubkey) !== pubkey256) {
      const msg = 'Certificate verification error: ' +
        `The public key of '${cert.subject.CN}' ` +
        'does not match our pinned fingerprint';
      return new Error(msg);
    }

    // Pin the exact certificate, rather then the pub key
    const cert256 = '25:FE:39:32:D9:63:8C:8A:FC:A1:9A:29:87:' +
      'D8:3E:4C:1D:98:DB:71:E4:1A:48:03:98:EA:22:6A:BD:8B:93:16';
    if (cert.fingerprint256 !== cert256) {
      const msg = 'Certificate verification error: ' +
        `The certificate of '${cert.subject.CN}' ` +
        'does not match our pinned fingerprint';
      return new Error(msg);
    }

    // This loop is informational only.
    // Print the certificate and public key fingerprints of all certs in the
    // chain. Its common to pin the public key of the issuer on the public
    // internet, while pinning the public key of the service in sensitive
    // environments.
      do {
        console.log('Subject Common Name:', cert.subject.CN);
        console.log('  Certificate SHA256 fingerprint:', cert.fingerprint256);

        hash = crypto.createHash('sha256');
        console.log('  Public key ping-sha256:', sha256(cert.pubkey));

        lastprint256 = cert.fingerprint256;
        cert = cert.issuerCertificate;
      } while (cert.fingerprint256 !== lastprint256);
    },
  }
}
*/
module.exports = {
  secureServer: secureServer,
  redirectHttp: redirectHttp
}