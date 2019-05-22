'use strict'
let chai = require('chai'),
    expect = chai.expect,
    assert = chai.assert,
    chaiHttp = require('chai-http'),
    fs = require('fs'),
    path = require('path'),
    { app } = require('../app'),
    { checkConnection, 
      checkHeaders, 
      checkBrowser, 
      checkData, 
      checkUploads,
      upload } = require('../validation'),
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
     file = {
        foto:
        {
          name: 'baddies.gif',
          data:
            `<Buffer 47 49 46 38 39 61 f4 01 0c 01 f7 ff 00 24 42 46 99 63 5c 05 08 10 b3 d5 ef 86 84 89 72 7a 85 22 39 43 09 18 22 a8 a6 aa 23 35 37 76 75 79 cc dc ed 72 ... >`,
          size: 1048382,
          encoding: '7bit',
          tempFilePath: '',
          truncated: false,
          mimetype: 'image/gif',
          md5: 'e7a6e5242a4bd8141d7227c38b32f684'
          // mv: [Function: mv]
        }
     }
chai.use(chaiHttp)
describe('VALIDATION OF INPUT', () => {
  describe('validate connection', () => {
    let allowed = { allowedSchemes: ['ftp', '*'] },
      connRequest
    before(() => {
      connRequest = chai.request(app)
    })
    it('should be able to parse and match request\'s protocol against a predetermined list', () => {
      connRequest.get('/').then(response => {
        checkConnection(response.req.agent, allowed, (err, success) => {
          if (err) {
            console.log(`${err.message}`)
            expect(success).to.be.equal(false)
          }
          else {
            console.log(`${response.req.agent.protocol} was matched in ${allowed.allowedSchemes}`)
            expect(success).to.equal(true)
          }
        })
      }).catch(e => {
        console.log(e.stack)
      })
    })
  })
  describe('validate headers', () => {
    let headerChecks

    beforeEach(() => {
      headerChecks = chai.request(app)
    })
    it('should have headers', done => {
      headerChecks.get('/').end((err, response) => {
        expect(response.req, 'bad bad not good').to.have.headers
        done()
      })
    })
    it('should check that headers match whitelist', done => {
      headerChecks.get('/').end((err, response) => {
        if (err) {
          console.log(err.message)
          expect(err).to.throw(err.message, 'There was a problem')
        } else {
          response.req.headers = headers
          checkHeaders(response.req, null, (error, success) => {
            if (error) {
              console.log(error.message)
              expect(success).to.be.false
            } else {
              console.log('we did it!')
              expect(success).to.be.true
            }
          })
        }
        done()
      })
    })
    it('should allow whitelist to be overridden', done => {
      headerChecks.get('/').end((err, response) => {
        if (err) {
          console.log(err.message)
          expect(err).to.throw(err.message, 'There was a problem')
        } else {
          response.req.headers = headers
          checkHeaders(response.req, response.req.headers, (error, success) => {
            if (error) {
              console.log(error.message)
              expect(success).to.be.false
            } else {
              console.log('we did it!')
              expect(success).to.be.true
            }
          })
        }
        done()
      })
    })
    it('should fail if the whitelist is blank', done => {
      headerChecks.get('/').end((err, response) => {
        if (err) {
          console.log(err.message)
          expect(err).to.throw(err.message, 'There was a problem')
        } else {
          response.req.headers = headers
          checkHeaders(response.req, " ", (error, success) => {
            if (error) {
              console.log(error.message)
              expect(success).to.be.false
            } else {
              console.log('we did it!')
              expect(success).to.be.true
            }
          })
        }
        done()
      })
    })
  })
  describe('validate browser', () => {
    let browserChecks
    let whitelists = require('../security/.whitelists.json')
    beforeEach(async () => {
      browserChecks = await chai.request(app)
    })
    after(async () => {
      whitelists['user-agent'] = []
      fs.writeFile(path.join(__dirname, '../security/.whitelists.json'), JSON.stringify(whitelists), err => {
        if (err) { console.log(err.message) }
      })
    })
    it('should have user-agent header', done => {
      browserChecks.get('/').end((err, response) => {
        expect(response.req, 'bad bad not good').to.have.header('user-agent')
        done()
      })
    })
    it('should add new user-agents to the whitelist in monitor mode', done => {
      browserChecks.get('/').end((err, response) => {
        response.req.headers = headers
        checkBrowser(response.req, 'monitor', (error, success, message) => {
          if (error) {
            console.log(error.code, error.message)
            expect(success).to.be.false
          } else {
            expect(whitelists['user-agent'].length).to.equal(1)
            assert.include(whitelists['user-agent'], 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.103 Safari/537.36', `${message}`)
            expect(success).to.be.true
          }
        })
        done()
      })
    })
    it('should block user-agents NOT on the whitelist in enforce mode', done => {
      browserChecks.get('/').end((err, response) => {
        response.req.headers = headers
        response.req.headers['user-agent'] = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:66.0) Gecko/20100101 Firefox/66.0'
        checkBrowser(response.req, 'enforce', (error, success) => {
          if (error) {
            console.log(error.code, error.message)
            expect(success).to.be.false
          } else {
            console.log(`Found user agent ${headers['user-agent']} on the list of allowed browsers`)
            assert.notInclude(whitelists['user-agent'], 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:66.0) Gecko/20100101 Firefox/66.0', 'value not in array')
            expect(success).to.be.true
          }
        })
        done()
      })
    })
  })
  describe('validate request', () => {
    // stretch goal
    it('should validate that the request is properly formmated')
    it('should detect & prevent use of and execution of code in the browser')
  })
  describe('validate data', () => {
    let data,
        rules,
        dCheck
    beforeEach(() => {
      dCheck = chai.request(app)
      data = {
        firstname: 'John',
        lastname: 'Doe',
        email: 'jdoe@email.com'
      },
        rules = {
          firstname: {
            presence: true,
            format: {
              pattern: "[a-zA-Z'-]+",
              flags: "i",
              message: 'only letters apostrophes and dashes allowed'
            },
            length: {
              minimum: 10
            }
          },
          lastname: {
            presence: {
              allowEmpty: true
            },
            format: {
              pattern: "[a-zA-Z'-]+",
              flags: "i",
              message: 'only letters apostrophes and dashes allowed'
            },
            length: {
              maximum: 10,
              tooLong: 'Sorry, the last name is too long'
            }
          },
          email: {
            email: true,
            presence: true
          }
        }
    })
    it('should check that the data matches a given ruleset', () => {
      dCheck.get('/').then(response => {
        response.req.headers = headers
        checkData(response.req, data, rules, (error, success) => {
          if (error) {
            console.log(error.code + " : " + error.message)
            expect(success).to.be.false
          } else {
            console.log('no problem, bro')
            expect(success).to.be.true
          }
        })
      }).catch(e => console.log(e.message))
    })
    it('data and ruleset MUST be non-empty objects', () => {
      dCheck.get('/thanks').then(response => {
        response.req.headers = headers
        checkData(response.req, {}, {}, (err, success) => {
          if (err) {
            console.log(err.code + ' : ' + err.message)
            expect(success).to.be.false
          } else {
            expect(success).to.be.true
          }
        })
      }).catch(e => console.log(e.message))
    })
    it('for every data value, there MUST be a matching rule', () => {
      dCheck.get('/register').then(response => {
        response.req.headers = headers
        checkData(response.req, data, rules.firstname, (err, success) => {
          if (err) {
            console.log(err.message)
            expect(success).to.be.false
          } else {
            expect(success).to.be.true
          }
        })
      }).catch(e => console.log(e.message))
    })
  })
  describe('validate uploads', () => {
    let uploadCheck

    beforeEach(() => {
      uploadCheck = chai.request(app)
      if (fs.existsSync('../uploads/fake-file.jpg')) {
        fs.unlink('../uploads/fake-file.jpg', err => {
          if (err) console.log(err.message)
        })
      }
    })

    it('should restrict file size', () => {
      uploadCheck.post('/register')
        .attach('files', fs.readFileSync(path.join(__dirname + '/fake-file.jpg')), 'fake-file.jpg')
        .then((result) => {
          result.req.headers = headers
          checkUploads(result.req, { saveLocation: '../uploads/', acceptableTypes: ['*'] }, (err, success) => {
            if (err) {
              console.log(err.message)
              expect(success).to.be.false
            } else {
              expect(success).to.be.true
            }
          })
        })
        .catch(error => {
          console.log(error)
        })
    })
    it('should restrict file type', done => {
      uploadCheck.post('/register')
        .attach('fake-foto', fs.readFileSync(path.join(__dirname + '/fake-file.jpg')), 'fake-file.jpg')
        .end((err, response) => {
          response.req.headers = headers
          checkUploads(response.req, { saveLocation: '../uploads/', acceptableTypes: ['gif', 'pdf', 'png'] }, (error, success) => {
            if (error) {
              console.log(error.code + ' : ' + error.message)
              expect(success).to.be.false
            } else {
              expect(success).to.be.true
            }
          })
        })
      done()
    })
    it('should strip inapporpriate characters from filename', done => {
      uploadCheck.post('/register')
        .attach('fake-foto', fs.readFileSync(path.join(__dirname + '/fake-file.jpg')), 'fake-file.jpg')
        .end((err, response) => {
          response.req.headers = headers
          checkUploads(response.req, { saveLocation: '../uploads/', acceptableTypes: ['jpg', '*'] }, (error, success) => {
            if (error) {
              console.log(error.code + " : " + error.message)
              expect(success).to.be.false
            } else {
              expect(success).to.be.true
            }
          })
        })
      done()
    })
    // it('should check file\'s magic number')
    it('should NOT upload files which fail conditions', done => {
      uploadCheck.post('/register')
        .attach('security-audit', fs.readFileSync(path.join(__dirname + '/security-audit.jpg')), 'security-audit.jpg')
        .end((err, response) => {
          response.req.headers = headers
          checkUploads(response.req, { saveLocation: '../uploads/', acceptableTypes: ['*'] }, (error, success) => {
            if (error) {
              console.log(error.code + " : " + error.message)
              expect(success).to.be.false
            } else {
              expect(success).to.be.true
            }
          })
        })
      done()
    })
  })
})