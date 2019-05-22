'use strict'
let p = require('./policy')
let pkgJson = p.read('./package.json')

var nq =
[{
  type: 'input',
  name: 'appName',
  message: 'Q0. What is the name of the application?',
  default: 'Get this from package.json file'
},
{
  type: 'list',
  name: 'type',
  message: 'Q1. Application Type : What kind of application is this? \n * Tip: How will MOST users interact with your application?',
  default: 1,
  choices: ['Desktop', 'Web', 'Mobile', 'Kiosk', 'Embedded/IoT (Controller)', 'API']
},
{
  type: 'input',
  name: 'hostname',
  message: "Q1.1 What is the application hostname? \n * Tip: How will users REACH your application, like: 'http://localhost:8080' or 'www.google.com'",
  default: 'localhost',
  when: function (answers) {
    var ask
    if (answers.type === 'Desktop' || answers.type === 'Embedded/IoT (Controller)') {
      ask = false
    } else {
      ask = true
    }
    return ask
  }
},
{
  // why ask this? Because the response may change the response headers that are set on the application
  type: 'confirm',
  name: 'exposure',
  message: "Q2. Application Accessibility : Will the application be accessible over the Internet? \n * Tip : if this is a possibility in the future, say 'Yes'",
  default: true,
  validate: function (answers) {
    if (answers.exposure !== 'Y' || answers.exposure !== 'N' || answers.exposure !== 'yes' || answers.exposure !== 'no') {
      return 'Invalid input. Please try again.'
    } else {
      return answers.exposure
    }
  },
  filter: Boolean
},
{
  type: 'confirm',
  name: 'access',
  message: "Q3. User Sign-in : Will your application require any kind of sign-in or authentication functionality in order to utilize certain routes or services? \n * Tip : if this is a possibility in the future, say 'Yes'",
  default: true
},
{
  type: 'list',
  name: 'sessions',
  message: "Q4. Sessions : Will the application have predetermined session lengths or can users be logged in indefinitely? \n * Tip : if this is a possibility in the future, say 'Yes'",
  default: 0,
  choices: ['User sessions have a set timeout', 'Users can be logged in indefinitely', 'Other session management scheme outside application']
},
{
  type: 'input',
  name: 'sessionLength',
  message: 'Q4.1 What is the default session length (TTL) in seconds?',
  default: 600,
  when: function (answers) {
    return answers.sessions === 'User sessions have a set timeout'
  },
  filter: Number
},
{
  type: 'confirm',
  name: 'secureTransport',
  message: "Q5. Connection Security : Does the application force secure transport (HTTPS, SSH, etc) throughout? \n * Tip : if your application responds to requests over non-secure means on any component say 'No'",
  default: true
},
{
  type: 'list',
  name: 'content',
  message: "Q6. Content Acquisition : Is all of the data/content generated and processed within your application? \n * Tip : if you plan to use external APIs at any point, choose the second answer. You'll have the opportunity to specify these sources later",
  default: 1,
  choices: [
    'All of the data and content comes from sources that I own or control',
    "Some of the data and content comes from sources that I don't own or control"
  ],
  when: function (answers) {
    var ask
    if (answers.type === 'API' || answers.type === 'Embedded/IoT (Controller)') {
      ask = false
    } else {
      ask = true
    }
    return ask
  }
},
{
  type: 'editor',
  name: 'contentSources',
  message: "Q6.1. Content Sources: Sweet! What are those sources? (JSON)\n * Tip: While specificity is more secure, it's also limiting. Use '*' operand for more flexible options. Use the formatting in the default",
  default: '{"default" : ["\'self\'"], "media" : ["\'self\'", "*.pinterest.com", "https://*.flickr.com", "ftp://video.domain.com:21"], "image" : ["\'self\'"], "style" : ["*.bootstrap.com", "https://materializecss.com", "\'self\'"], "script" : ["\'self\'"], "connect": ["http://localhost:5000", "\'self\'"], "frame" : ["\'none\'"]}',
  when: function (answers) {
    var floop = "Some of the data and content comes from sources that I don't own or control"
    return answers.content === floop
  },
  filter: function (value, e) {
    try {
      return JSON.parse(value)
    } catch (e) {
      return 'Unable to successfully format this object => ' + e
    }
  }
},
{
  type: 'confirm',
  name: 'forms',
  message: 'Q7. Forms: Will your application utilize input forms for data collection?\n * Tip : Consider collection of ratings, feedback, reviews, search, profiles etc...',
  default: true
},
{
  // why ask about cache? Because some generated data and user-provided data may be considered sensitive, and we want to make sure that we DON'T cache that information
  type: 'confirm',
  name: 'cacheStrategy',
  message: "Q8. Caching Strategy: Do you have any intention of introducing a caching layer or using a Content Delivery Network (CDN)?\n * Tip : If this is a possibility in the future, choose 'yes'.",
  default: true
},
{
  type: 'input',
  name: 'cacheTtl',
  message: 'Q8.1. Cache Time To Live (TTL): For MOST public data generated by the application, how long (in seconds) should this information be cached?\n * Tip : Shorter TTLs will require more requests of the application origin; longer TTLs may result in stale, invalid data. You can override this on a per-route basis',
  default: 15780000,
  when: function (answers) {
    return answers.cacheStrategy
  },
  validate: function (value) {
    var valid = !isNaN(parseInt(value))
    return valid || 'Please enter a number'
  },
  filter: Number
},
{
  type: 'input',
  name: 'deployment',
  message: 'Q9. Application Hosting : Where will application be deployed & hosted? \n * Tip : Looking for GCP, Serverless, AWS, Rackspace, Heroku or similar',
  default: 'locally hosted',
  // need a validation for this
  filter: String
},
{
  type: 'input',
  name: 'logging',
  message: 'Q10. Logging and Auditing: Where will application logs be stored? (absolute path)',
  default: function () {
    if (pkgJson instanceof Error) {
      return `/var/log/appName`
    } else {
      return `/var/log/${pkgJson.name}/`
    }
  }
}]

var confirmDelete = [
  {
    type: 'confirm',
    name: 'deleteConfirm',
    message: 'Are you sure you wish to delete the policy? This action cannot be undone\n',
    default: true
  }]
var confirmDeleteForce = [
  {
    type: 'confirm',
    name: 'deleteForceConfirm',
    message: 'Are you sure? This will not only delete the policy, but also uninstall any associated npm modules.\n',
    default: true
  }]
var confirmSettings = [
  {
    type: 'confirm',
    name: 'settingsConfirm',
    message: 'Is this ok?\n',
    default: true
  }]
var restoreDefault = [
  {
    type: 'confirm',
    name: 'restore',
    message: 'Are you sure? This will completely overwrite your configurations & restore the default policy.\n',
    default: true
  }]
exports.nq = nq
exports.confirmDelete = confirmDelete
exports.confirmSettings = confirmSettings
exports.confirmDeleteForce = confirmDeleteForce
exports.restoreDefault = restoreDefault
