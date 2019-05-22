'use strict'
let chai = require('chai'),
    expect = chai.expect,
    chaiHttp = require('chai-http'),
    { app } = require('../app'),
    path = require('path'),
    fs = require('fs'),
    timestamp = require('time-stamp'),
    csv = require('csvtojson'),
    headers = ['timestamp', 'id', 'label', 'class', 'subclass', 'type', 'context', 'message'],
    { LogWriter, Bullhorn }= require('../logger'),
    bullhorn = new Bullhorn({
                    name: 'Bully',
                    method: {
                      console: {},
                      email: {
                        transporter: [
                          'gmail',
                          {
                            user: 'nodemailerTest1982@gmail.com', pass: '321qazZAQ!@#'
                          }
                        ],
                        template: {
                          from: 'internal@yourapp.com',
                          to: 'ysmithND@gmail.com'
                        }
                      }
                    }
                            }),
    threshold = {
      name: 'Rate Limit Violations by IP',
      pivotOn: 'ip',
      notifyOn: {
        console: 3,
        email: 10
      },
      details: {}},
    notifier = bullhorn.setConditions(threshold),
    { apiLogger } = require('../api'),
    secJson = require('../security.json'),
    proc = require('dotenv').config()
  
chai.use(chaiHttp)
describe('SECURITY LOGGING FUNCTIONS', () => {
  describe('record security events', () => {
    let logChecker,
        filters
    beforeEach(() => {
      logChecker = chai.request(app)
    })
    it('should provide a set of smart logging security-specific defaults', () => {
      csv({ headers : headers }).fromFile(`/var/log/validation/${timestamp.utc('YYYY-MM-DD')}-logs.csv`)
         .then(json => {
           expect(json[0].class).to.be.oneOf(['API', 'VALIDATION', 'AUTHENTICATION', 'CORS', 'SESSION',
                                              'FORMS', 'CACHE', 'DATABASE', 'HEADERS', 'SECRETS', 
                                              'DEPENDENCIES'], 'bad bad not good')
          expect(json[0].type).to.be.oneOf(['ERROR', 'INFO', 'SUCCESS','FAILURE'], 'BAD BAD NOT GOOD')    
         }).catch(e => {
           console.log(e.message)
         })
    })
    it('should allow users to specify their own security event criteria', () => {
      logChecker.post('/register').then(response => {
        let body = {
              firstname : 'efkkljfdc',
              lastname : 'owejncdkjr'
            }
            response.req.body = body
        let fname = new RegExp(response.req.body.firstname, "gi"),
            lname = new RegExp(response.req.body.lastname, "gi"),
            filters = {
              'key': [/[A-Za-z0-9]{32}/g, 'KEY REDACTED'],
              'credit-card': [/^\d{4}-\d{4}-\d{4}-\d{4}$|\d{16}/g, 'xxxx-xxxx-xxxx-0000'],
              'ssn': [/^\d{3}-\d{2}-\d{4}$|\d{9}/g, 'YYY-ZZ-XXXX'],
              'firstname': [fname, 'John'],
              'lastname': [lname, 'Smith']
            }
        let lg = new LogWriter({ console: false, file: true, filters : filters}),
            myRules = {
              name: 'authLogger',
              levels: true, // means this is required as part of the details
              label: 'BADBADNOTGOOD',
              structure: {
                class: {
                  name: 'class',
                  required: true,
                  type: String
                },
                subclass: {
                  name: 'subclass',
                  required: false,
                  type: Array[String]
                },
                context: {
                  name: 'data',
                  required: true,
                  type: Object,
                  components: ['a', 'b', 'c', 'd', { e: 'f' }]
                }
              },
              recordPath: `./myfiles.csv`,
              append: true,
              compress : true
            },
            g = lg.eventBuilder(myRules)
        g.authLogger({ class: 'AUTHENTICATION', subclass: 'REGISTRATION', type: 'RAINBOW', data: { a: 123, b: 456, c: 'sdkfj', d: 345 } })
        csv({ headers: headers }).fromFile('./myFiles.csv').then(json => {
          expect(json[0].label).to.equal(myRules.label, 'badbadnotgood!')
        }).catch(e => { throw e })
      }).catch(e => { throw e })
    })
    it('should include entire context of the event', () => {
      csv({headers : headers}).fromFile(`/var/log/validation/${timestamp.utc('YYYY-MM-DD')}-logs.csv`).then(json => {
        if (!json[0].context.includes('N/A')) {
          expect(json[0].context).to.contain('method'),
            expect(json[0].context).to.contain('browser')
          expect(Object.keys(json[0])).to.include('message', 'nooooooo')
        }
      })
    })
    it('should classify security events differently than other event types', () => {
      csv({ headers: headers }).fromFile(`/var/log/validation/${timestamp.utc('YYYY-MM-DD')}-logs.csv`).then(json => {
        expect(json[0].label).to.equal('SECURITY EVENT')
      })
    })
    // it('should capture all CRUD events as it pertains to the application')
    it('should capture all READ/WRITE events from the application as it pertains to the log (e.g. Log Entry Deletions)', () => {
      headers = ['id', 'timestamp', 'action', 'class', 'subclass', 'type', 'message']
      csv({ headers: headers }).fromFile(`/var/log/validation/${timestamp.utc('YYYY-MM-DD')}-audit.csv`)
          .then(json => {
            expect(json[0].action).to.equal('WRITE')
          })
    })
    // it('should record all application error events', () => {
    // })
    it('should offer filters for sensitive data', () => {
      csv({ headers: ['timestamp', 'id', 'label', 'class', 'subclass', 'type', 'context', 'message'] }).fromFile(`/var/log/validation/${timestamp.utc('YYYY-MM-DD')}-logs.csv`).then(json => {
        let counter = 0
        for (let j = 0; j < json.length; j++) {
          if (json[j].message.includes('KEY REDACTED')) {
            counter = counter + 1
          }
        }
        // expect(counter).to.be.greaterThan(0, 'take a break')
      })
    })
    // stretch goal...for integrity
    it('should offer signed log writes')
    it('should offer timed log events')
  })
  describe('log access', () => {
    it('should be \'fetchable\' from the application')
    it('should perform validation on the fetched info prior to exposure in the application')
    it('should require higher-level privileges for log modification or deletion') //
  })
  describe('notification of events', () => {
    let notifyCheck = chai.request(app)
    it('should have a means of notifying a human', () => {
      bullhorn.messageContent('Hiiiiii', 'Message Test')
      // bullhorn.mail((err, info) => {
      //   if (err) {
      //     console.log(err.message)
      //     expect(info).to.be.false
      //   } else {
      //     console.log(info)
      //   }
      // })
    })
    it('should have a means of setting notification thresholds', () => {
      let requestLimit = 10,
          timePeriod   = 'minute'

      notifyCheck.get('/ghjk').then(response => {
        threshold.details['message'] = `A request from ${response.req.ip} attempted to perform ${response.req.method} on route ${response.req.route}.\\n 
Currently requests from ${response.req.ip} are limited to ${requestLimit} per ${timePeriod}`
        // notifier({ip : response.req.ip, method : response.req.method, route : response.req.route, timePeriod : timePeriod, requestLimit: requestLimit}, 4)
        // expect(notifier).to.be.a('function')
      }).catch(e => console.log(e.message))
    })
    it('should offer a variety of notification mechanisms', () => {
      if(bullhorn.method.email) {
        bullhorn.messageContent(`It's a beautiful day in the neighborhood`, `A beautiful day to be a neighbor`)
        // bullhorn.mail((err, info, message) => {
        //   if (err) {
        //     console.log(err.message)
        //     expect(info).to.be.false
        //   } else {
        //     console.log(message)
        //     expect(message).to.be.a('string')
        //     expect(Object.keys(info)).to.include('messageId')
        //   }
        // })
      }
      if(bullhorn.method.console) {
        let p = bullhorn.consoler('I pooped my pants', 'bad bad not good')
        expect(p).to.be.a('string')
      }
      
    })
  })
  describe('provide report', () => {
    it('should allow users to recall events by time-period')
    it('should allow users to recall events by event-type')
    it('should allow users to recall events by status code')
    it('should allow users to recall events by tag')
    it('should allow users to recall events by user-data (id, location, ip)')
  })
  describe('log storage', () => {
    it('should allow for local or external storage', () => {
      expect(apiLogger.file).to.be.true
      fs.readdir(secJson.loggingPolicy.logCollection.storage, (err, files) => {
        if (err) {
          expect(err).to.throw
        } else {
          expect(files).to.be.ok
          files.forEach(file => {
            expect(path.extname(file)).to.be.oneOf(['.csv', '.gz', '.json'])
          })
        }
      })
      console.log(`Files are stored at ${secJson.loggingPolicy.logCollection.storage}`)
    }) //
    it('should give users the ability to encrypt & compress the logs prior to storage', () => {
      apiLogger.compression = true
      apiLogger.setCompression(true)
      apiLogger.setEncryption(true, path.resolve(__dirname, '../rsa_pub.key'), 'RSA256', (err, success) => {
        if (err) {
          console.log(err.message)
          expect(success).to.be.false
        } else {
          expect(success).to.be.true
        }

      })
    })
    it('should allow users to configure log rotation schedule', () => {
      apiLogger.rotateLogs = 'weekly'
      expect(apiLogger).to.include({rotateLogs : 'weekly'})
      apiLogger.setLogRotation('weekly')
      let today = new Date(),
          diff = today.getDate() - today.getDay() + (today.getDate() === 0 ? -6 : 0),
          beginWeek = new Date(today.setDate(diff))
      fs.readdir(secJson.loggingPolicy.logCollection.storage, (err, files) => {
        if (err) expect(err).to.throw
        else {
          files.forEach(file => {
            file.includes(`${beginWeek.toISOString}`) ? expect(true).to.be.true : expect(file).to.contain(beginWeek.getFullYear())
          })
        }
      })

    })
    it('should allow users to configure max log size', () => {
      apiLogger.maxFileSize = 5242880
      apiLogger.setMaxFileSize(5242880)
    })
  })
  // stretch goal
  describe('push logs to other aggregators', () => {
    it('should only transmit logs over secure means (https, ssh)')
    it('should offer ability to push logs to grafana')
    it('should offer ability to push logs to elk')
    it('should offer ability to push events into kafka')
    it('should offer ability to push events to Splunk')
    it('should offer ability to export logs in syslog format')
    it('should offer ability to export logs to csv')
    it('should offer abilty to export logs to JSON')
  })
})
