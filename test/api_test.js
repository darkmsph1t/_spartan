'use strict'
let chai = require('chai'),
    chaiHttp = require('chai-http'),
    expect = chai.expect,
    config = require('dotenv').config(),
    should = chai.should(),
    { app } = require('../app'),
    path = require('path'),
    fs = require('fs'),
    k = '12345678qwertyui12345678qwertyui',
    d = Date.now(),
    { apiAccessCtrl,
      apiMethodCheck,
      apiRateLimit,
      apiKeyRevocation,
      apiTokenMonitor,
      apiDataCheck,
      keyComber
    } = require('../api'),
    headers = {
      'content-type': 'application/json',
      'host': 'localhost:5000',
      'connection': 'keep-alive',
      'cache-control': 'max-age=0',
      'upgrade-insecure-requests': '1',
      'user-agent':
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.103 Safari/537.36',
      'dnt': '1'
    },
    mockUname = 'john@gmail.com',
    mockPass = 'pass',
    mockRole = 'administrator',
    token,
    key,
    jwt = require('njwt')
    // jwt = require('jsonwebtoken')

chai.use(chaiHttp)
describe('SECURE API DELIVERY', () => {
  // what must the api look like to be considered 'secure'?
  // - must limit privileged actions (update/delete) to users with the correct permissions
  // - must ensure that the request matches the allowed methods
  // - must protect against brute forcing and replay through rate limiting ++ timestamps

  describe('api access control', () => { // we must ensure that only authenticated users can access the api
    let authCheck,
      date = Math.floor(Date.now() / 1000) - 120,
      cert = process.env.SECRET,
      claims = {
        sub: mockUname,
        exp: Date.now() + (1000 * 60 * 60 * 24), // expires in 24 hours
        iss: 'http://localhost:5000',
        scope: ['read', 'update', 'delete', 'create'],
        role: 'admins, users, self',
        aud: ['/profile/user?id=' + mockUname, '/register', '/users/add'],
        nbf: date
      },
      t
    beforeEach(() => {
      authCheck = chai.request(app)
      token = jwt.create(claims, cert)
      t = token.compact()
    })
    it('should inspect the token\'s validity', () => {
      token.body.nbf = Date.now()
      t = token.compact()
      authCheck.get('/')
        .set('Authorization', `Bearer ${t}`)
        .then((response) => {
          headers.authorization = `Bearer ${t}`
          response.req.headers = headers
          apiAccessCtrl(response.req, undefined, (error, success, message) => {
            if (error) {
              expect(success).to.be.false
            } else if (success === null) {
              console.log(message)
            } else {
              console.log(message)
              expect(success).to.be.true
            }
          })
        })
    })
    it('should evaluate whether the request matches the scoped actions', () => { // this is currently JWT only
      token.body.scope = ['create', 'update', 'delete']
      t = token.compact()
      authCheck.get('/register')
        .set('Authorization', `Bearer ${t}`)
        .then((response) => {
          response.req.headers = headers
          response.req.headers['authorization'] = `Bearer ${t}`
          apiAccessCtrl(response.req, undefined, (error, success, message) => {
            if (error) {
              console.log(error.message)
              expect(success).to.be.false
              expect(error.status).to.equal(403)
            } else {
              console.log(message)
              expect(success).to.be.true
            }
          })
        }).catch(error => {
          console.log(error.stack)
        })
    })
    it('should evaluate the validity of refresh tokens')
    it('should validate the requested resource is within the token\'s audience', () => {
      authCheck.get('/')
        .set('Authorization', `Bearer ${t}`)
        .then((response) => {
          //  console.log(response.req[Object.getOwnPropertySymbols(response.req)[1]])
          headers.authorization = `Bearer ${t}`
          response.req.headers = headers
          apiAccessCtrl(response.req, undefined, (error, success, message) => {
            if (error) {
              console.log(error.message)
              expect(success).to.be.false
            } else if (success === null) {
              console.log(message)
            } else {
              console.log(message)
              expect(success).to.be.true
            }
          })
        }).catch(e => {
          console.log(e.stack)
        })
    })
  })
  describe('key handling', () => { // we must be able to revoke access to the api
    let keyCheck,
      options = {},
      query = { 'apiKey': k, 'someData': 'data' },
      params = { 'apiKey': k, 'someData': 'data' },
      cookies = { 'apiKey': k },
      protocol
    beforeEach(() => {
      keyCheck = chai.request(app)
      headers.authorization = `API Key ${k}`
      protocol = 'http:'
    })
    it('should ensure that keys are transmitted securely', () => {
      keyCheck.get('/register')
        .set('Authorization', `API Key ${k}`)
        .then((response) => {
          response.req.headers = headers
          response.req.protocol = response.req.agent.protocol
          apiAccessCtrl(response.req, { key: k }, (err, success, message) => {
            if (err) {
              console.log(err.status, message)
              expect(success).to.be.false
            } else {
              console.log(message)
              expect(success).to.be.true
            }
          })
        }).catch(e => {
          console.log(e.message)
        })
    })
    it('should offer automatic key revocation option', () => {
      keyCheck.get('/register')
        .set('Authorization', `API Key ${k}`)
        .then((response) => {
          response.req.headers = headers
          response.req.protocol = 'http:'
          apiAccessCtrl(response.req, { revokeKey: true, key: k }, (err, success, message) => {
            if (err) {
              console.log(err.status, message)
              expect(success).to.be.false
            } else {
              console.log(message)
              expect(success).to.be.true
            }
          })
        }).catch(e => {
          console.log(e.message)
        })
    })
    it('should inspect key\'s validity', () => { // checks to see if a key is expired, revoked or otherwise cannot be used to perform the requested action
      keyCheck.get('/register')
        .set('Authentication', `API Key ${k}`)
        .then((response) => {
          response.req.headers = headers
          options.allowed = ['get', 'options', 'head']
          options.key = k
          response.req.protocol = 'https:'
          apiAccessCtrl(response.req, options, (err, success, message) => {
            if (err) {
              console.log(err.status, message)
              expect(success).to.be.false
            } else {
              console.log(message)
              expect(success).to.be.true
            }
          })
        }).catch(e => {
          console.log(e.message)
        })
    })
    it('should detect keys in header, query parameter or cookie', () => {
      keyCheck.get('/')
        .set('Authorization', `API Key ${k}`)
        .send({ apiKey: k })
        .query({ 'apiKey': k, 'someData': 'data' })
        .then(response => {
          response.req.headers = headers
          response.req.query = query
          response.req.params = params
          response.req.cookies = cookies
          response.req.protocol = protocol
          let foundKeys = keyComber(response.req)
          console.log(foundKeys.status, foundKeys.message)
          expect(foundKeys.allKeys).to.be.an('array').that.contains(k)
          expect(foundKeys.foundAt).to.be.an('object')
        })
        .catch(e => {
          console.log(e.message)
        })
    })
    // stretch goal
    it('should throw an error for keys transmitted in clear text (e.g. no encryption)')
  })
  describe('prevent method abuse', () => { // demonstrate that there's no way to override the method
    let methCheck,
      options

    beforeEach(async () => {
      methCheck = await chai.request(app)
      options = {
        allowed: ['put', 'head'],
        key: k
      }
      delete headers['X-HTTP-METHOD']
      delete headers['X-HTTP-METHOD-OVERRIDE']
      delete headers['X-METHOD-OVERRIDE']
    })
    it('should allow limited method override for specific resources', () => {
      options.allowed = ['put', 'trace', 'delete']
      methCheck.delete('/register')
        .type('form')
        .send({
          '_method': 'delete',
          'first': 'John',
          'last': 'Doe',
          'email': 'jdoe@email.com'
        })
        .then((response) => {
          response.req.headers = headers
          apiMethodCheck(response.req, options, (err, success) => {
            if (err) {
              console.log(err.status, err.message)
              expect(err.status).to.equal(405)
              expect(success).to.be.false
            } else {
              expect(success).to.be.true
            }
          })
        })
        .catch(e => {
          console.log(e.message)
        })
    })
    it('should require a key or token for modifying resources', () => {
      options.key = undefined
      methCheck.put('/register')
        .type('form')
        .send({
          '_method': 'delete',
          'first': 'John',
          'last': 'Doe',
          'email': 'jdoe@email.com'
        })
        .then((response) => {
          response.req.headers = headers
          apiMethodCheck(response.req, options, (err, success) => {
            if (err) {
              console.log(err.status, err.message)
              expect(err.status).to.equal(400)
              expect(success).to.be.false
            } else {
              expect(success).to.be.true
            }
          })
        })
        .catch(e => {
          console.log(e.message)
        })
    })
    it('should throw a 405 code if the request method is not allowed by the target resource', () => {
      methCheck.delete('/register')
        .type('form')
        .send({
          '_method': 'delete',
          'first': 'John',
          'last': 'Doe',
          'email': 'jdoe@email.com'
        })
        .then((response) => {
          response.req.headers = headers
          apiMethodCheck(response.req, options, (err, success) => {
            if (err) {
              console.log(err.status, err.message)
              expect(err.status).to.equal(405)
              expect(success).to.be.false
            } else {
              expect(success).to.be.true
            }
          })
        })
        .catch(e => {
          console.log(e.message)
        })
    })
    it('should throw an error if method override is attempted, but not allowed by policy', () => {
      methCheck.put('/register')
        .type('form')
        .send({
          '_method': 'put',
          'first': 'John',
          'last': 'Doe',
          'email': 'jdoe@email.com'
        })
        .then((response) => {
          response.req.headers = headers
          apiMethodCheck(response.req, options, (err, success) => {
            if (err) {
              console.log(err.status, err.message)
              expect(success).to.be.false
            } else {
              expect(success).to.be.true
            }
          })
        })
        .catch(e => {
          console.log(e.message)
        })
    })
    it('should check request headers for method override headers X-HTTP-Method', () => {
      methCheck.get('/')
        .set('X-HTTP-METHOD', 'PUT')
        .then(response => {
          headers['X-HTTP-METHOD'] = 'PUT'
          delete headers['X-HTTP-METHOD-OVERRIDE']
          delete headers['X-METHOD-OVERRIDE']
          response.req.headers = headers
          options.allowed = ['get', 'head', 'options']
          apiMethodCheck(response.req, options, (err, success) => {
            if (err) {
              console.log(err.status, err.message)
              expect(success).to.be.false
            } else {
              expect(success).to.be.true
            }
          })
        }).catch(e => {
          console.log(e.message)
        })
    })
    it('should check request headers for method override header X-HTTP-METHOD-OVERRIDE', () => {
      methCheck.post('/register')
        .set('X-HTTP-METHOD-OVERRIDE', 'DELETE')
        .then(response => {
          headers['X-HTTP-METHOD-OVERRIDE'] = 'DELETE'
          delete headers['X-HTTP-METHOD']
          delete headers['X-METHOD-OVERRIDE']
          response.req.headers = headers
          options.allowed = ['post', 'head', 'options']
          apiMethodCheck(response.req, options, (err, success) => {
            if (err) {
              console.log(err.status, err.message)
              expect(success).to.be.false
            } else {
              expect(success).to.be.true
            }
          })
        }).catch(e => {
          console.log(e.message)
        })
    })
    it('should check request headers for method override header X-METHOD-OVERRIDE', () => {
      methCheck.get('/thanks')
        .set('X-METHOD-OVERRIDE', 'TRACE')
        .then(response => {
          headers['X-METHOD-OVERRIDE'] = 'TRACE'
          delete headers['X-HTTP-METHOD']
          delete headers['X-HTTP-METHOD-OVERRIDE']
          response.req.headers = headers
          options.allowed = ['get']
          apiMethodCheck(response.req, options, (err, success) => {
            if (err) {
              console.log(err.status, err.message)
              expect(success).to.be.false
            } else {
              expect(success).to.be.true
            }
          })
        }).catch(e => {
          console.log(e.message)
        })
    })
    it('should check query parameters for method override indicators', () => {
      methCheck.get('/')
        .query({ '_method': 'PUT' })
        .then(response => {
          response.req.query = { '_method': 'PUT' }
          response.req.headers = headers
          // delete headers['X-HTTP-METHOD']
          // delete headers['X-HTTP-METHOD-OVERRIDE']
          // delete headers['X-METHOD-OVERRIDE']
          apiMethodCheck(response.req, { allowed: ['get', 'post', 'head'], key: k }, (err, success) => {
            if (err) {
              console.log(err.status, err.message)
              expect(success).to.be.false
            } else {
              console.log('wut')
              expect(success).to.be.true
            }
          })
        })
        .catch(e => {
          console.log(e.stack)
        })
    })
    // stretch goal
    it('should detect use of method modification software (e.g. method-override)')
  })
  describe('rate limiting', () => { // demonstrate rate limits & monitoring
    let rLimit,
      options

    beforeEach(() => {
      rLimit = chai.request(app)
      options = {
        key: k,
        throttle: false,
        instaBlock: false
      }
    })
    it('should prevent a specific user from making too many requests', () => {
      rLimit.get('/').then(response => {
        response.req.headers = headers
        apiRateLimit(response.req, options, -10, 'second', (err, success, msg) => {
          if (err) {
            console.log(err.message)
            expect(success).to.be.false
          } else {
            console.log(msg)
            expect(success).to.be.true
          }
        })
      }).catch(e => console.log(e.message))
    })
    it('should prevent all users from making too many requests to the api', () => {
      options.key = undefined
      rLimit.get('/register').then(response => {
        response.req.headers = headers
        apiRateLimit(response.req, options, 1, 'minute', (err, success) => {
          if (err) {
            console.log(err.message)
            expect(success).to.be.false
          } else {
            expect(success).to.be.true
          }
        })
      }).catch(e => console.log(e.message))
    })
    it('should block access to the route for a period of time', () => {
      options.instaBlock = {
        duration: 5 * 60 * 1000, // in milliseconds...sorry!
        from: d
      }
      rLimit.get('/thanks').then(response => {
        response.req.headers = headers
        apiRateLimit(response.req, options, 1, 'second', (err, success) => {
          if (err) {
            console.log(err.message)
            expect(success).to.be.false
          } else {
            expect(success).to.be.true
          }
        })
      }).catch(err => console.log(err.message))
    })
    it('should SLOW DOWN access to the route for a period of time', () => { // this is tarpitting
      options.throttle = {
        within: 10,
        slowDownTo: 10,
        per: 'minute'
      }
      rLimit.get('/profile').then(response => {
        response.req.headers = headers
        apiRateLimit(response.req, options, 10, 'second', (err, success, message) => {
          if (err) {
            console.log(err.message)
            expect(success).to.be.false // <-- need to relook at this
          } else {
            console.log(message)
            expect(success).to.be.true
          }
        })
      }).catch(err => console.log(err.message))
    })
  })
  describe('replay prevention', () => { // should ensure that each request is unique in order to prevent brute force and replay attacks
    let replay,
      timestamp
    before(() => {
      replay = chai.request(app)
    })
    it('should check that each request has a unique timestamp', () => {
      replay.get('/')
        .set('timestamp', Date.now())
        .then((response) => {
          // would be good to be able to have an actual method for this...
          expect(response.req[Object.getOwnPropertySymbols(response.req)[1]].timestamp).to.include('timestamp') // looking for the timestamp header
        }).catch(e => {
          console.log(e.message)
        })
    })
  })
  // stretch goal
  describe('data returned', () => { // only return as much data is needed to answer the question
    it('should validate query parameters before sending')
    it('should validate returned data for sensitive information')
  }) 
})