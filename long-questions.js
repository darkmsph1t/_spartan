'use strict';
var inquirer = require('inquirer');
var fs = require('fs');

console.log("Thanks for using _spartan! Here's how it works: \n\n * After answering a few questions, _spartan will generate a policy file (security.json).\n\n * Based upon the contents, _spartan generates the basic boilerplate code (security.js) which can be referenced in your application.\n\n * _spartan will also update the application's package.json file if additional dependencies are required.\n\n");

/* 1. Check for package.json file */
// Ask for path to package.json. if no package.json => throw error && report: "package.json file not found. Please run \"npm init\" to create the package.json file and run _spartan later"

//Assuming package.json exists
// 1. get app name from package.json, pass to appName variable
var questions = [
  {
    type : 'list',
    name : 'dependencyPolicy',
    message : "How do you want to handle vulnerabilities in application dependencies?",
    choices : [ 'Track vulnerabilities discovered in application dependencies in the context of the application',
                'This is handled elsewhere in the technology stack (compensatingControl)',
                'Not dealing with this right now (no controls)'
              ]
  },
  {
    type : 'list',
    name : 'vulnHandling',
    message : "How should we handle vulnerabilities found in application dependencies?",
    choices : [ 'Fix automatically (may introduce breaking changes)',
                'Save audit report for later review'
              ],
    when : function(answers) {
      return answers.dependencyPolicy == 'Track vulnerabilities discovered in application dependencies in the context of the application';
    }
  },
  {
    type : 'input',
    name : 'auditPath',
    message : "Path to audit reports: ",
    default : '/var/log/appName/',
    when : function(answers) {
      return answers.vulnHandling == 'Save audit report for later review';
    }
  },
  {
    type: 'list',
    name : 'databasePolicy',
    message : 'How is interaction with databases handled?',
    choices : [
        'The application manages database interaction',
        'This is handled someplace else in the techology stack (compensatingControl)',
        'Not dealing with this right now (no controls)'
    ],
  },
  {
    type : 'editor',
    name : 'dbsUsed',
    message : 'What database(s) are in use and for what purpose? (JSON)',
    default : '{"MongoDB" : ["sessions", "whitelisting"], "Cassandra" : ["accounts", items"], "Postgress" : ["transactions", "credit-cards"]}',
    when : function(answers){
      return answers.databasePolicy == 'The application manages database interaction'
    },
    // validate : function(data) {
    //   try {
    //     JSON.parse(data);
    //   }
    //   catch {
    //     return "JSON format is required";
    //   }
    // },
    filter : function(value, e){
      try {
        return JSON.parse(value);
      }
      catch (e) {
       return "Unable to successfully format this object => " + e;
      }
    }
  },
  {
    type : 'confirm',
    name : 'dbAccess',
    message : 'Does your application directly access (read, write, update, delete) any local or remote database?',
    default : true,
    when : function(answers){
      return answers.databasePolicy == 'The application manages database interaction'
    }
  },
  {
    type : 'confirm',
    name : 'dbSecurity',
    message : 'Are the database(s) configured to accept connections over TLS/SSL only?',
    default : true,
    when : function(answers){
      return answers.dbAccess == true;
    }
  },
  {
    type : 'confirm',
    name : 'dbRbac',
    message : 'Do the database(s) enforce role based access control (RBAC)?',
    default : true,
    when : function(answers){
      return answers.dbAccess == true;
    }
  },
  {
    type : 'confirm',
    name : 'dbValidation',
    message : 'Validate data prior to storage?',
    default : true,
    when : function(answers){
      return answers.dbAccess == true;
    }
  },
  {
    type : 'confirm',
    name : 'dbEncrypt',
    message : 'Encrypt data prior to storage?',
    default : true,
    when : function(answers){
      return answers.dbAccess == true;
    }
  },
  {
    type: 'list',
    name : 'inputValidationPolicy',
    message : 'How is user input being validated?',
    choices : [
        'The application will validate user input',
        'This is handled someplace else in the techology stack (compensatingControl)',
        'Not dealing with this right now (no controls)'
    ]
  },
  {
    type : 'confirm',
    name : 'syntaxValidation',
    message : 'Enable syntax (length, type, etc...) validation?',
    default : true,
    when : function(answers){
      return answers.inputValidationPolicy == 'The application will validate user input';
    }
  },
  {
    type: 'list',
    name : 'dataModels',
    message : 'How does the application define and interact with data models?',
    choices : [
        'JSON Schema',
        'middleware',
        'Other'
    ],
    when : function(answers){
      return answers.inputValidationPolicy == 'The application will validate user input';
    }
  },
  {
    type: 'checkbox',
    name : 'dataEncoding',
    message : 'What in the application is subject to encoding?',
    choices : [
        {name : 'HTML', checked : true},
        {name : 'JavaScript', checked : true},
        'CSS',
        'None'
    ],
    when : function(answers){
      return answers.inputValidationPolicy == 'The application will validate user input';
    }
  },
  {
    type : 'editor',
    name : 'whitelistValidation',
    message : 'Which application components require whitelists for validation (e.g. \'cors\')? (string array)',
    default : '[\'cors\', \'headers\', \'dns\']',
    when : function(answers){
      return answers.inputValidationPolicy == 'The application will validate user input';
    }
  },
  {
    type : 'confirm',
    name : 'attemptSanitize',
    message : 'Attempt sanitization on inputs?',
    default : true,
    when : function(answers){
      return answers.inputValidationPolicy == 'The application will validate user input';
    }
  },
  {
    type : 'confirm',
    name : 'convertType',
    message : 'Convert type inconsistencies?',
    default : true,
    when : function(answers){
      return answers.inputValidationPolicy == 'The application will validate user input';
    }
  },
  {
    type: 'list',
    name : 'validationFailures',
    message : 'How should the application handle validation failures?',
    choices : [
        'Reroute with error message',
        'Kill authenticated sessions (aggressive)',
        'Other'
    ],
    when : function(answers){
      return answers.inputValidationPolicy == 'The application will validate user input';
    }
  },
  {
    type: 'list',
    name : 'accessControlPolicy',
    message : 'Where is access control handled?',
    default : 0,
    choices : [
        'The application handles access control',
        'This is handled someplace else in the techology stack (compensatingControl)',
        'Not dealing with this right now (no controls)'
    ]
  },
  {
    type : 'list',
    name : 'appAuth',
    message : "How will users authenticate to the app? ",
    default : 0,
    choices : ['username/password', "oauth/openid", "saml", "no log in required"],
    when : function(answers) {
      return answers.accessControlPolicy == 'The application handles access control';
    }
  },
  {
    type : 'confirm',
    name : 'blankUsername',
    message : 'Blank usernames allowed?',
    default : false,
    when : function(answers){
      return answers.appAuth == 'username/password';
    }
  },
  {
    type: 'list',
    name : 'usernameGeneration',
    message : 'How are usernames generated?',
    default : 1,
    choices : [
        'email',
        'randomly generated',
        'user created (like twitter)',
        'phone number',
        'other'
    ],
    when : function(answers){
      return answers.appAuth == 'username/password';
    }
  },
  {
    type: 'input',
    name: 'passwdLength',
    message: 'What is the required password length?',
    default : 12,
    when : function(answers){
      return answers.appAuth == 'username/password';
    },
    validate: function(value) {
      var valid = !isNaN(parseFloat(value));
      return valid || 'Please enter a number';
    },
    filter: Number
  },
  {
    type: 'input',
    name: 'upperPasswdLength',
    message: 'How many uppercase characters are required?',
    default : 3,
    when : function(answers){
      return answers.appAuth == 'username/password';
    },
    validate: function(value, answers) {
      if (value > answers.passwdLength){
        return "This value cannot be greater than the total password length"
      }
      var valid = !isNaN(parseFloat(value));
      return valid || 'Please enter a number';
    },
    filter: Number
  },
  {
    type: 'input',
    name: 'numberPasswdLength',
    message: 'How many numbers (0-9) are required?',
    default : 3,
    when : function(answers){
      return answers.appAuth == 'username/password';
    },
    validate: function(value, answers) {
      if (value > answers.passwdLength){
        return "This value cannot be greater than the total password length"
      }
      if (value + answers.upperPasswdLength > answers.passwdLength){
        return "This value combined with other requirements exceeds the total password length"
      }
      var valid = !isNaN(parseFloat(value));
      return valid || 'Please enter a number';
    },
    filter: Number
  },
  {
    type: 'input',
    name: 'specCharPasswdLength',
    message: 'How many special characters are required?',
    default : 3,
    when : function(answers){
      return answers.appAuth == 'username/password';
    },
    validate: function(value, answers) {
      if (value > answers.passwdLength){
        return "This value cannot be greater than the total password length"
      }
      if (value + answers.upperPasswdLength + answers.numberPasswdLength > answers.passwdLength){
        return "This value combined with other requirements exceeds the total password length"
      }
      var valid = !isNaN(parseFloat(value));
      return valid || 'Please enter a number';
    },
    filter: Number
  },
  {
    type: 'input',
    name: 'specCharsAllowed',
    message: 'Which special characters are required?',
    default : '!@#$%^&()',
    when : function(answers){
      return answers.specCharPasswdLength;
    },
    validate: function(string) {
      var pass = string.match(/([\D\s])\W+/g);
      if (pass) {
        return true;
      }
        return 'Non alphanumeric (0-9,a-z,A-Z) characters please';
      },
    filter : String
  },
  {
    type: 'input',
    name: 'automaticLockout',
    message: 'How many attempts before an account is locked out?',
    default : 3,
    when : function(answers){
      return answers.passwdLength;
    },
    validate: function(value, answers) {
      var valid = !isNaN(parseFloat(value));
      return valid || 'Please enter a number';
    },
    filter: Number
  },
  {
    type: 'input',
    name: 'lockoutPeriod',
    message: 'How long (in minutes) before users can try again?',
    default : 5,
    when : function(answers){
      return answers.passwdLength;
    },
    validate: function(value, answers) {
      var valid = !isNaN(parseFloat(value));
      return valid || 'Please enter a number';
    },
    filter: Number
  },
  {
    type : 'confirm',
    name : 'passwdChange',
    message : 'Force password change after lockout?',
    default : true,
    when : function(answers){
      return answers.automaticLockout;
    }
  },
  {
    type : 'confirm',
    name : 'accountRecovery',
    message : 'Force password change for account recovery?',
    default : true,
    when : function(answers){
      return answers.automaticLockout;
    }
  },
  {
    type : 'confirm',
    name : 'allowPasswdReuse',
    message : 'Allow password reuse?',
    default : false,
    when : function(answers){
      return answers.appAuth == 'username/password';
    }
  },
  {
    type : 'confirm',
    name : 'logFailedAttempts',
    message : 'Keep track of failed login attempts?',
    default : true,
    when : function(answers){
      return answers.appAuth == 'username/password';
    }
  },
  {
    type : 'input',
    name : 'loginFailureLogs',
    message : "Path to failed login logs: ",
    default : '/var/log/appName/failedLogins/',
    when : function(answers) {
      return answers.logFailedAttempts;
    }
  },
  {
    type : 'confirm',
    name : 'multifactorAuth',
    message : 'Does the application utilize multifactor authentication?',
    default : false,
    when : function(answers) {
      return answers.accessControlPolicy == 'The application handles access control';
    }
  },
  {
    type : 'editor',
    name : 'mfaTypes',
    message : 'Which multifactor authentication methods are in use?',
    default : '[\'Google Authenticator\', \'Duo\', \'FIDO\', \'Authy\']',
    when : function(answers){
      return answers.multifactorAuth;
    }
  },
  {
    type : 'list',
    name : 'rbacEnabled',
    message : 'Will the application offer multiple access levels/permissions?',
    default : 0,
    choices : ['Yes', 'This is handled elsewhere in the technology stack (compensatingControl)', 'No authorization scheme in place at this time'],
    when : function(answers) {
      return answers.accessControlPolicy == 'The application handles access control';
    }
  },
  {
    type : 'editor',
    name : 'rbacPermissions',
    message : 'Please define the roles and permissions in use (JSON):',
    default : '{ \'viewer\' : \'read-only\', \'user\' : \'viewer+write\',\'reviewer\' : \'user+approve/reject\',\'moderator\' : \'reviewer+grant/revoke access\',\'administrator\' : \'moderator+create/delete roles+view logs\'}',
    when : function(answers) {
      return answers.rbacEnabled == 'Yes';
    }
  },
  {
    type : 'list',
    name : 'formsPolicy',
    message : 'How should form data be handled?',
    default : 0,
    choices : ['The application will generate forms and validate form data', 'This is handled elsewhere in the technology stack (compensatingControl)', 'Not dealing with this right now (no controls)'],
  },
  {
    type : 'confirm',
    name : 'jsonAccept',
    message : 'Accept form data as JSON (set content-type to \'application/json\')?',
    default : true,
    when : function(answers) {
      return answers.formsPolicy == 'The application will generate forms and validate form data';
    }
  },
  {
    type : 'confirm',
    name : 'disableAutocomplete',
    message : 'Disable autocomplete?',
    default : true,
    when : function(answers) {
      return answers.formsPolicy == 'The application will generate forms and validate form data';
    }
  },
  {
    type : 'confirm',
    name : 'csrfProtection',
    message : 'Enable Cross Site Request Forgery Protections?',
    default : true,
    when : function(answers) {
      return answers.formsPolicy == 'The application will generate forms and validate form data';
    }
  },
  {
    type : 'list',
    name : 'sessionsPolicy',
    message : 'Where is session management handled?',
    default : 0,
    choices : ['The application handles sessions', 'This is being handled somewhere else in my technology stack (compensatingControl)', 'Not handling this right now (no control)'],
  },
  {
    type: 'input',
    name: 'sessionLength',
    message: 'How long (in minutes) should user sessions last? (integer)',
    default : 60,
    when : function(answers){
      return answers.sessionsPolicy == 'The application handles sessions';
    },
    validate: function(value) {
      var valid = !isNaN(parseFloat(value));
      return valid || 'Please enter a number';
    },
    filter: Number
  },
  {
    type: 'input',
    name: 'sessionIdle',
    message: 'How long (in minutes) should sessions idle before logout? (integer)',
    default : 10,
    when : function(answers){
      return answers.sessionsPolicy == 'The application handles sessions';
    },
    validate: function(value) {
      var valid = !isNaN(parseFloat(value));
      return valid || 'Please enter a number';
    },
    filter: Number
  },
  {
    type : 'confirm',
    name : 'cookieTransport',
    message : 'Do you want to force cookies to be transmitted over secure transport?',
    default : true,
    when : function(answers) {
      return answers.sessionsPolicy == 'The application handles sessions';
    }
  },
  {
    type: 'input',
    name: 'sessionIdle',
    message: 'What is the max age (in minutes) of cookies? (integer)',
    when : function(answers){
      return answers.sessionsPolicy == 'The application handles sessions';
    },
    validate: function(value) {
      var valid = !isNaN(parseFloat(value));
      return valid || 'Please enter a number';
    },
    filter: Number
  },
  {
    type : 'confirm',
    name : 'cookiesToScripts',
    message : 'Do you want to allow other scripts to access cookies (not the browser)?',
    default : false,
    when : function(answers) {
      return answers.sessionsPolicy == 'The application handles sessions';
    }
  },
  {
    type : 'confirm',
    name : 'cookiesToSites',
    message : 'Do you want to allow other sites to receive your application\'s cookies?',
    default : false,
    when : function(answers) {
      return answers.sessionsPolicy == 'The application handles sessions';
    }
  },
  {
    type : 'confirm',
    name : 'concurrentLogins',
    message : 'Does the application allow concurrent/simultaneous logins?',
    default : false,
    when : function(answers) {
      return answers.sessionsPolicy == 'The application handles sessions';
    }
  },
  {
    type: 'checkbox',
    name : 'reauth',
    message : 'When should users reauthenticate?',
    choices : [
        {name : 'On TTL Expiration?', checked : true},
        {name : 'Upon privilege escalation', checked : true},
        {name : 'On idle time expiration', checked : true },
        'None of these'
    ],
    when : function(answers){
      return answers.sessionsPolicy == 'The application handles sessions';
    }
  },
  {
    type: 'checkbox',
    name : 'autoLogout',
    message : 'When should the application automatically logout?',
    choices : [
        {name : 'On TTL Expiration?', checked : true},
        {name : 'Upon privilege escalation', checked : true},
        {name : 'Window or Tab Closure', checked : true },
        'None of these',
    ],
    when : function(answers){
      return answers.sessionsPolicy == 'The application handles sessions';
    }
  },
  {
    type : 'list',
    name : 'corsPolicy',
    message : 'How are cross-origin requests handled?',
    default : 0,
    choices : ['The application will moderate cross-origin requests', 'The application will not allow cross-origin requests (same-origin)','This is handled somewhere else in the technolgy stack (compensatingControl)', 'Not dealing with this right now (no control)'],
  },
  {
    type : 'list',
    name : 'whitelistSpec',
    message : 'Secure configuration of this policy typically requires specification of a whitelist. Would you like to do that now?',
    default : 1,
    choices : [
      'Specify now in the questionnaire',
      'Pass in whitelist location (flatfile)',
      'I don\'t want to specify this now'
    ],
    when : function(answers){
      return answers.corsPolicy == 'The application will moderate cross-origin requests'
    }
  },
  {
    type : 'editor',
    name : 'corsWhitelist',
    message : 'Great! See default for example formatting (JSON)',
    default :'{"domain" : {"name" : "example.com", "includeSubdomains" : true, "restrictToSchema" :  "https", "port" : 443, "methods" : ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],"credsRequired" : true }}',
    when: function(answers){
      return answers.whitelistSpec == 'Specify now in the questionnaire'
    },
    filter : function(value, e){
      try {
        return JSON.parse(value);
      }
      catch (e) {
       return "Unable to successfully format this object => " + e;
      }
    }
  },
]
inquirer.prompt(questions).then(answers => {
  console.log('\nApplication Security Policy:\n');
  console.log(JSON.stringify(answers, null, '  '));
});



/* Create a git branch called 'security' */
// git checkout -b security
