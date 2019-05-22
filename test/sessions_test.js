'use strict'
let chai = require('chai'),
    expect = chai.expect,
    chaiHttp = require('chai-http'),
    { app } = require('../app'),
    { CookieInspector, StoneWall} = require('../session'),
    uuidv4 = require('uuid/v4')

chai.use(chaiHttp)

// protects against the disclosure, capture, prediction, brute force or fixation of session IDs
describe('SESSION SECURITY', () => {
  describe('inspect generated session ids', () => {
    let cookie = {
        JSESSIONID : uuidv4()
        },
        idInpsect
    beforeEach(() => {
      idInpsect = chai.request(app)
    })
    it('should warn against easily fingerprinted session id names', () => {
      idInpsect.get('/register').then(response => {
        let chocolateChip = new CookieInspector()
        chocolateChip.cookieMonster(cookie, response.req, (err, success) => {
          if (err) {
            expect(success).to.be.false
            // expect(chocolateChip.cookieMonster(cookie)).to.throw(err)
          }
        })
      })
    })
    it('should warn against session ids that are less than 128-bit...e.g. 32-char', () => {
      idInpsect.get('/').then(response => {
        let oatmeal = new CookieInspector(),
            cookie = { sid: uuidv4() },
            headers = {
            'user-agent': 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.103 Safari/537.36'
            }
        response.req.headers = headers
        oatmeal.cookieMonster(cookie, response.req, (err, success) => {
          if (err) {
            expect(success).to.be.false
          }
        })
      }).catch(e => console.log(e))
    })
    it('should check that the session id actually came from the server')
  })  
  describe('generate secure cookies', () => {
      let cookieRequest
    beforeEach(() => {
      cookieRequest = chai.request(app)
    })
    it('should enforce the security settings on cookie', () => {
        cookieRequest.get('/register')
                     .then(response => {
                       expect(response.headers['set-cookie'][0]).to.include('Secure' && 'HttpOnly', 'bad bad not good')
                      })
                     .catch(e => console.log(e.message))
    })
    it('should set the max-age property on all cookies', () => {
      cookieRequest.get('/register')
        .then(response => {
          expect(response.headers['set-cookie'][0]).to.include('Max-Age', 'bad bad not good')
        })
        .catch(e => console.log(e.message))
    })
    it('should allow for HOST and SECURE prefixes', () => {
      cookieRequest.get('/register')
        .then(response => {
          expect(response.headers['set-cookie'][0]).to.include('_Host-', 'bad bad not good')
        })
        .catch(e => console.log(e.message))
    })
  })
  describe('inspect cookie settings', () => {
    let cookieInspect
    beforeEach(() => {
      cookieInspect = chai.request(app)
    })
    it('should error if the cookie does not have the httpOnly flag', () => {
      let ci = `id=${uuidv4()}`,
          sugar = new CookieInspector(),
          c = { foo : uuidv4()}
      cookieInspect.get('/auth')
                   .set('Cookie', ci)
                   .then(response => {
                    let headers = {
                       'user-agent': 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.103 Safari/537.36'
                     }
                     response.req.headers = headers
                     sugar.cookieMonster(c, response.req, (err, success) => {
                       if (err) {
                         expect(success).to.be.false
                       } else {
                         expect(success).to.be.true
                       }
                     })

                   })
                   .catch(e => console.log(e))
    })
    it('should error if cookie does not have a secure flag', () => {
      cookieInspect.get('/').then(response => {
        let headers = {
              'user-agent': 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.103 Safari/537.36'
            },
            chocolate = new CookieInspector()
        response.req.headers = headers
        chocolate.cookieMonster({id : uuidv4()}, response.req, (err, success) => {
          if (err) {
            // console.log(err.status, err.message)
            expect(success).to.be.false
          } else {
            expect(success).to.be.true
          }
        })
      }).catch(e => console.log(e))
    })
    it('should warn if the cookie is not using the hostOnly flag', () => {
      cookieInspect.get('/').then(response => {
        let headers = {
                'user-agent': 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.103 Safari/537.36'
              },
            snickerdoodle = new CookieInspector()
        response.req.headers = headers
        snickerdoodle.cookieMonster({id : uuidv4()}, response.req, (err, success) => {
          if (err) {
            // console.log(err.status, err.message)
            expect(success).to.be.false
          } else {
            expect(success).to.be.true
          }
        })
      }).catch(e => console.log(e))
    })
  })
  describe('set up secure session access', () => {
    it('should limit session length', () => {
      let stonewall = new StoneWall() 
      let opts = stonewall.secureSession('hiiiii')
      expect(opts.cookie.maxAge).to.not.equal(null)
      expect(opts.cookie.maxAge).to.be.a('number')
      expect(opts).to.be.an('object')
    })
    it('should force idle session drops', () => {
      let castle = new StoneWall(),
          drawbridge = castle.secureSession('moat')
      drawbridge.cookie.maxAge = 6000
      drawbridge.rolling = false // <-- causes the maxAge to roll over on each request
    })
    // it('should invalidate session id on window close') // this would be for client-side...
    it('should regenerate a session id upon authentication') // to prevent session fixation
    // it('should WARN of concurrent logins and ERROR if not allowed by policy')
  })
  describe('invaliate tokens?', () => {
    let tokenCheck
    beforeEach(() => {
      tokenCheck = chai.request(app)
    })
    it('should invalidate session ids on logout', () => {
      let mansion = new StoneWall(),
          spire = mansion.secureSession('gate'),
          cookie = spire.cookie
      tokenCheck.get('/login')
                .then(response => {
                }).catch(e => console.log(e))
    })
    it('should invalidate cookies after the maxAge has expired')
    it('should invalidate session ids once the session ttl has expired')
  })
  xdescribe('csrf token inspection?')
  // oauth ++ sessions?
})
