'use strict'
let fs = require('fs'),
    secJson = require('./security.json'),
    logLocation = secJson.loggingPolicy.logCollection.storage,
    label = 'SECURITY EVENT',
    timestamp = require('time-stamp'),
    id = require('shortid'),
    createCsvWriter = require('csv-writer').createObjectCsvWriter,
    csvWriter = createCsvWriter({
      path: `${logLocation}/${timestamp.utc('YYYY-MM-DD')}-logs.csv`,
      header: [{ id: 'timestamp', title: 'Timestamp' },
               { id: 'id', title: 'ID' },
               { id: 'label', title: 'Label' },
               { id: 'class', title: 'Class' },
               { id: 'subclass', title: 'Subclass' },
               { id: 'type', title: 'Type' },
               { id: 'context', title: 'Description' },
               { id: 'message', title: 'Message' }
              ],
      append: true
    }),
    targz = require('targz'),
    rSched,
    mSize,
    compressionSetting,
    encryptionSetting,
    nodemailer = require('nodemailer'),
    colors = require('colors'),
    counter = 0

const getCount = () => {
  return counter
}
const setCount = (value) => {
  counter = counter + value
}
const auditor = (auditFilePath, message, id, tstamp, classType, subclass, type, action) => {
  let auditWriter = createCsvWriter({
        path : auditFilePath,
        header: [
          {id : 'id', title: 'id'},
          {id : 'timestamp', title: 'timestamp'},
          {id : 'action', title: 'action'},
          {id: 'class', title: 'class'},
          {id: 'subclass', title: 'subclass'},
          {id: 'type', title: 'type'},
          {id: 'message', title: 'message'}
        ],
        append: true
      }),
      audits = [],
      auditRecord = {
        id : id,
        timestamp : tstamp,
        action : action,
        class : classType,
        subclass, subclass,
        type : type,
        message : message
      }
      audits.push(auditRecord)
  if(!fs.existsSync(auditFilePath)) {
    let stream = fs.createWriteStream(auditFilePath)
    stream.write('ID, TIMESTAMP, ACTION, CLASS, SUBCLASS, TYPE, MESSAGE')
    stream.close()
  }
  auditWriter.writeRecords(audits).then(() => {
    // console.log(`Executed ${action} on ${auditFilePath} at ${timestamp.utc('YYYY-MM-DD.HH:mm:ms')}`)
  }).catch(e =>  {
    let m = `Action ${action} was not recorded to ${auditFilePath} due to an error, ${e.message}`
    console.log(m)
  })
}
const checkPath = (pathToCheck) => {
  if(!fs.existsSync(pathToCheck)) {
    let stream = fs.createWriteStream(pathToCheck)
    stream.write(" \n")
    stream.close()
  }
}
const filterData = (details, filters) => {
  for (let d in details) {
    for (let f in filters) {
      if (typeof details[d] === 'string' && details[d].match(filters[f][0])) {
        details[d] = details[d].replace(filters[f][0], filters[f][1])
      }
    }
  }
  return details
}
const decompress = (src, dest)  => {
  targz.decompress({
    src: src,
    dest: dest
  }, (err => {
    if (err) console.log(err)
  }))
}
const compress = (src, dest) => {
  targz.compress({
    src: src,
    dest: dest
  }, (err => {
    if (err) console.log(err)
  }))
}
/**
 * @name changeLogs
 * @description checks the rotation schedule set on the logger and returns the timestamp prefix matching the schedule specs
 * @returns {TimeRanges} timestamp string value
 */
const changeLogs = (sched) => {
  let append
  switch(sched) {
    case 'yearly'  :
      append = timestamp.utc('[YYYY]')
      break
    case 'monthly' :
      append = timestamp.utc('[YYYY-MM]')
      break
    case 'weekly'  :
      let today = new Date(),
          diff = today.getDate() - today.getDay() + (today.getDay() === 0 ? -6 : 0),
          startWeek = new Date(today.setDate(diff))
      append = timestamp.utc(`[${startWeek.getUTCFullYear()}-${startWeek.getUTCMonth()}-${startWeek.getUTCDate()}]`)
        break
    case 'hourly'  : 
      append = timestamp.utc('[YYYY-MM-DD.HH]')
      break
    default :
      append = timestamp.utc('[YYYY-MM-DD]') 
  }
  return append
}
class LogWriter {
  constructor(options) {
    this.console = options.console
    this.file = options.file
    this.filters = options.filters
  }
  /**
   * @name logSettings
   * @description fetches existing settings on the logger
   */
  get logSettings() {
    return {
      console : this.console,
      file : this.file,
      filters : this.filters
    }
  }
  /**
   * @name logSettings
   * @description overloads existing settings for the logger and applies new settings
   * @param {Object} settings object with console, file and filter options set
   */
  set logSettings (settings) {
    this.console = settings.console,
    this.file = settings.file
    this.filters = settings.filters
  }
  get compression () {
    return this._compression
  }
  set compression (c) {
    this._compression = c
  }
  get rotateLogs () {
    return this._rotationSchedule
  }
  set rotateLogs (sched) {
    this._rotationSchedule = sched
  }
  get maxFileSize () {
    return this._maxSize
  }
  set maxFileSize (m) {
    this._maxSize = m
  }
  /**
   * @description class method to enable or disable log encryption prior to storage, requires a private/public key pair
   * @param {Boolean} enc
   * @param {String} pathToKey path to encryption key (if using public/private key pair, the PUBLIC key goes here)
   * @param {String} alg encryption algorithm to be used
   * @param {Function} callback collects errors and messages
   * @returns {Function}
   */
  setEncryption (enc, pathToKey, alg, callback) {
    encryptionSetting = enc
    this._encryption = enc
  }
  /**
   * @name setCompression
   * @description class method to enable or disable compression
   * @param {Boolean} comp 
   */
  setCompression (comp) {
    compressionSetting = comp
    this._compression = comp
  }
  setLogRotation(sched) {
    rSched = sched
    this._rotationSchedule = sched
  }
  /**
   * @name setMaxFileSize 
   * @description class method to set the max file size of logs
   * @param {Number} maxSize 
   * @returns void
   */
  setMaxFileSize (maxSize) {
    mSize = maxSize
    this._maxSize = maxSize
  }
  /**
   * @name eventBuilder
   * @description allows users to specify their own security event criteria
   * @param {Object} eventCriteria object containing : event name, levels to watch for, event label, and structure. Structure is an open-ended object, but can contain criteria name, requirement, expected type, and associated components to capture 
   * @returns {Function} returns a function with the properties specified
   */
  eventBuilder(eventCriteria) {
    try {
      let csvMetaData = {}
      if (!eventCriteria) {
        let err = new Error('logging/missing-criteria')
        err.code = 'logging/missing-criteria'
        err.message = 'Criteria for event structure is required but was not found.'
        throw err
      }
      // name & label are required
      if (!eventCriteria.name) {
        let err = new Error('logging/missing-name')
        err.code = 'logging/missing-name'
        err.message = 'A name is required for the event you want to define'
        throw err
      } else if (!eventCriteria.label) {
        let err = new Error('logging/missing-label')
        err.code = 'logging/missing-label'
        err.message = 'A label is required for the event you want to define'
        throw err
      } else if (!eventCriteria.structure) {
        let err = new Error('logging/missing-event-structure')
        err.code = 'logging/missing-event-structure'
        err.message = 'The compnents of the event to be logged must be defined'
        throw err
      } else { // nothing
      } 
      if (eventCriteria.recordPath) {
        checkPath(eventCriteria.recordPath)
        csvMetaData.path = eventCriteria.recordPath
      }
      if (eventCriteria.append === true) {
        csvMetaData.append = true
      }
      // build headers for the csv file
      let header = []
      header.push({id : 'timestamp', name: 'timestamp'})
      header.push({ id: 'id', name: 'id' })
      header.push({ id: 'label', name: 'label' })
      for (let k in eventCriteria.structure) {
          let newObj = {
            id: (eventCriteria.structure[k].name).toString(),
            title: (eventCriteria.structure[k].name).toString()
          }
          header.push(newObj)
      }
      csvMetaData.header = header
      return {
        [eventCriteria.name] : (d, f) => {
          try {
            let w = createCsvWriter(csvMetaData),
                details = []
            d = filterData(d,f)    
            d['timestamp'] = timestamp.utc('YYYY-MM-DD.HHmm.ms')
            d['id'] = id.generate()
            d['label'] = eventCriteria.label    
            for (let i in eventCriteria.structure) {
                if (eventCriteria.structure[i].required === true &&
                  !Object.keys(d).includes(eventCriteria.structure[i].name)) {
                    let err = new Error('logging/missing-required-fields')
                    err.message = `Field ${eventCriteria.structure[i].name} is required and cannot be undefined`
                    err.code = 'logging/missing-required-fields'
                    throw err
                }
                if (typeof d[eventCriteria.structure[i].name] === 'function') {
                  let err = new Error('logging/dangerous-practice')
                  err.message = `Type of ${eventCriteria.structure[i].name} appears to be a function. This exposes the application to arbitrary code execution vulnerabilities upon log parsing.`
                  err.code = 'logging/dangerous-practice'
                  throw err
                }
                if (typeof d[eventCriteria.structure[i].name] === 'object') {
                  d[eventCriteria.structure[i].name] = JSON.stringify(d[eventCriteria.structure[i].name])
                  let c = d[eventCriteria.structure[i].name]
                  for (let h in c) {
                    if (typeof c[h] === 'function') {
                      let err = new Error('logging/dangerous-practice')
                      err.message = `Type of ${eventCriteria.structure[i].name} appears to be a function. This exposes the application to arbitrary code execution vulnerabilities upon log parsing.`
                      err.code = 'logging/dangerous-practice'
                      throw err
                    }
                  }
                }
                if (d[eventCriteria.structure[i].name] instanceof Array) {
                  for (let l = 0; l < d[eventCriteria.structure[i].name].length; l++) {
                    if (typeof d[eventCriteria.structure[i].name][l] === 'function') {
                      let err = new Error('logging/dangerous-practice')
                      err.message = `Type of ${eventCriteria.structure[i].name} appears to be a function. This exposes the application to arbitrary code execution vulnerabilities upon log parsing.`
                      err.code = 'logging/dangerous-practice'
                      throw err
                    }
                  }
                }
                details.push(d)
                // if (eventCriteria.compress) {
                //   decompress(`${path.dirname(csvMetaData.path)}/${path.basename(csvMetaData.path)}.tar.gz`, 
                //              path.dirname(csvMetaData.path))
                // }
                w.writeRecords(details).then(() => {
                  // if (eventCriteria.compress) {
                  //   compress(path.dirname(csvMetaData.path),
                  //            `${path.dirname(csvMetaData.path)}${path.basename(csvMetaData.path)}-log.tar.gz`)
                  // }
                  console.log(`Whew! Wrote to Log File`)
                }).catch(e => {throw e})
            }
          } catch (e) {
            throw e
          }
        }
      }
    } catch (e) {
      throw e
    }
  }
  writer(details) {
    details = filterData(details, this.filters)
    let arr = [],
        time = this._rotationSchedule ? changeLogs(this._rotationSchedule) : timestamp.utc('YYYY-MM-DD')
    details['label'] = label
    details['timestamp'] = `[${timestamp.utc('YYYY-MM-DD')}T${timestamp.utc('HH:mm:ss.ms')}]`
    details['id'] = id.generate()
    arr.push(details)
    if (this.console === true) {
      console.log(details)
    }
    if (this.file === true) {
      checkPath(`${logLocation}/${time}-logs.csv`)
      // if(this._compression === true) {
      //   decompress(`${logLocation}/${time}-log.tar.gz`,
      //     `${logLocation}/`)
      // }
      csvWriter.writeRecords(arr).then(() => {
        // compress(`${logLocation}/`,
        //   `${logLocation}/${time}-log.tar.gz`)
        auditor(`${logLocation}/${timestamp.utc('YYYY-MM-DD')}-audit.csv`, 
                `Accessed file ${logLocation}/${time}-logs.csv`,
                details.id, details.timestamp, details.class, details.subclass, details.type, 'WRITE')
      }).catch(e => {
        let m = `Could not write to file ${logLocation}/${time}-logs.csv due to an error, ${e.message}`
        console.log(m)
      })
    }
  }
}
/**
 * @name Bullhorn
 * @description watches and notifies specified recipient of identified event occurences
 * @param {Object} options - name & notification methods (email, console)
 */
class Bullhorn {
  constructor(options) {
    this.name = options.name
    this.method = options.method
  }
  consoler (subject, content) {
    if(content instanceof Object) {
      content = JSON.stringify(content)
    }
    let message = `
ATTENTION: \n
-----------\n
You asked to be notified of the following condition
${subject}\n
which occurred at ${new Date()}\n
Here are the details : ${content}\n
Please consult the logs at ${logLocation} for more information`
    console.log(message.yellow)
    return message
  }
  messageContent(subject, content) {
    if (content instanceof Object) {
      content = JSON.stringify(content)
    }
    this.method.email.template.subject = subject
    this.method.email.template.text = content
    return this.method.email
  }
  mail(callback) {
    if(this.method.email) {
      let t = {
        service : this.method.email.transporter[0],
        auth : this.method.email.transporter[1]
      }
      let transporter = nodemailer.createTransport(t)
      transporter.sendMail(this.method.email.template, (err, info) => {
        if (err) { return callback(err, false, null)}
        else { 
          let message = `here is the message id of the sent email: ${info.messageId}`
          return callback(null, info, message) 
        }
      })
    }
  }
  setConditions(conditions) {
    this._conditions = conditions
    /**
     * @description function to handle notification events
     * @param {Object} whatToWatch object of which details to include in the notification
     * @param {Number} [howMuchToCount=1] value of how much this notification should count. Set this to the max value in the threshold if you want to be notified instantly
     */
    return (whatToWatch, howMuchToCount) => {
      if (howMuchToCount) {
        setCount(howMuchToCount)
      } else {
        setCount(1)
      }
      for (let w in whatToWatch) {
        conditions.details[w] = whatToWatch[w]
      }
      if (conditions.notifyOn.console && conditions.notifyOn.console <= counter) {
        this.consoler(conditions.name, conditions.details)
        if (conditions.resetOnNotify) {
          counter = 0
        }
      } else {
        console.log(`There are ${conditions.notifyOn.console - counter} events left`)
      }
      if(conditions.notifyOn.email && conditions.notifyOn.email <= counter) {
        this.messageContent(conditions.name, conditions.details)
        this.mail((err, info, msg) => {
          if (err) console.log(err.message)
          else {
            console.log(msg)
          }
        })
        if (conditions.resetOnNotify) {
          counter = 0
        }
      } else {
        console.log(`There are ${conditions.notifyOn.email - counter} events left before the next escalation`)
      }
    }
  }
}
module.exports = {
  LogWriter: LogWriter,
  Bullhorn : Bullhorn
}