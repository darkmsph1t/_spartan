'use strict'
var chalk = require('chalk')
var { spawn } = require('child_process')
var fs = require('fs')
var path = require('path')
var pathToBoilerPlate = path.resolve('./security.js')

// should add in a function to validate security.json before writing boilerplate
function validatePolicy () {

}
function matches (allPkgs, currentPkgs) {
  // get packages from package.json
  // var temp = Object.keys(pkgJson.dependencies);
  return currentPkgs.filter(x => allPkgs.includes(x))
}
function diff (old, current) {
  try {
    return old.filter(x => !current.includes(x))
  } catch (e) {
    console.log(e)
  }
}
function removeModules (modules) {
  var remove = spawn('npm', ['uninstall', modules])
}

function installModules (modules) {
  var install = spawn('npm'['install', '--save', modules])
}
function appDepBp (p) {
  try {
    var appDepCode = ''
    var appDepMods = []
    appDepCode += '/*---------------------------------------Application Dependencies-------------------------------------*/\n'
    appDepCode += 'var { spawn } = require(\'child_process\');\n'
    appDepCode += 'function checkAppDependencies(){\n'
    appDepCode += '\t var check = spawn(\'snyk\', [\'test\', \'--file=package.json\']);\n'
    appDepCode += '\t var monitor = spawn(\'snyk\', [\'monitor\']);\n'
    appDepCode += '\treturn {\n'
    appDepCode += '\t"check" : check,\n'
    appDepCode += '\t"monitor" : monitor\n\t}\n}\n'
    appDepCode += 'module.exports.checkAppDependencies = checkAppDependencies;\n'
    return {
      'appDepCode': appDepCode,
      'appDepMods': appDepMods
    }
  } catch (e) {
    console.log(e)
  }
}
function accessCtrlBp (p) {
  try {
    var accessCtrlCode = ''
    var accessCtrlMods = []
    accessCtrlCode += '/*----------------------------------------Access Controls-----------------------------------------*/\n'
    if ((p.accessControlsPolicy.authenticationPolicy.supportedMethods).includes('local') || (p.accessControlsPolicy.authenticationPolicy.supportedMethods).includes('uname/passwd')) {
      accessCtrlCode += '//>>>>>>>>>>>>>>>>>>>>>>>>>>local auth (username/password)>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n'
      accessCtrlCode += 'var local = spawn(\'npm\', [\'install\', \'passport-local\']);\n'
      accessCtrlCode += 'var LocalStrategy = require(\'passport-local\').Strategy;\n'
      accessCtrlCode += 'passport.use(new LocalStrategy(\n{\n'
      accessCtrlCode += 'usernameField: \'email\',\n passwordField: \'passwd\'\n},\n'
      accessCtrlCode += 'function(username, password, done) {\n'
      accessCtrlCode += 'User.findOne({ username: username }, function (err, user) {\n'
      accessCtrlCode += 'if (err) { return done(err); }\n'
      accessCtrlCode += 'if (!user) {\n return done(null, false, { message: \'Incorrect username or password.\' });\n}\n'
      accessCtrlCode += 'if (!user.validPassword(password)) {\n return done(null, false, { message: \'Incorrect username or password.\' });\n}\nreturn done(null, user);\n});\n}\n));\n'
      accessCtrlCode += '//inside app.js\n'
      accessCtrlCode += 'app.post(\'/login\',passport.authenticate(\'local\', { successRedirect: \'/\',\n failureRedirect: \'/login\',\n failureFlash: true })\n);\n'
      // need to do passwords + bcrypt
    }
    if ((p.accessControlsPolicy.authenticationPolicy.supportedMethods).includes('openId')) {
      accessCtrlCode += '//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>federated auth (openid, saml) >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n'
      accessCtrlCode += '//openid\n'
      accessCtrlCode += 'var openId = spawn(\'npm\', [\'install\', \'passport-openid\']);\n'
      accessCtrlCode += 'var OpenIDStrategy = require(\'passport-openid\').Strategy;\n'
      accessCtrlCode += 'passport.use(new OpenIDStrategy({\n'
      accessCtrlCode += 'returnURL : \'http://www.example.com/auth/openid/return\',\n'
      accessCtrlCode += 'realm : \'http://www.example.com/\',\n'
      accessCtrlCode += 'profile : false\n},\n'
      accessCtrlCode += 'function(identifier, done) {\n'
      accessCtrlCode += 'User.findOrCreate({ openId: identifier }, function(err, user) {\n'
      accessCtrlCode += 'done(err, user);\n});\n}\n));\n'
      accessCtrlCode += '//inside app.js\n'
      accessCtrlCode += 'app.post(\'/auth/openid\', passport.authenticate(\'openid\'));\n'
      accessCtrlCode += 'app.get(\'/auth/openid/return\',\n'
      accessCtrlCode += 'passport.authenticate(\'openid\', { successRedirect: \'/\',\n failureRedirect: \'/login\' }));\n'
    }
    if ((p.accessControlsPolicy.authenticationPolicy.supportedMethods).includes('saml')) {
      accessCtrlCode += 'var saml = spawn(\'npm\', [\'install\', \'passport-saml\']);\n'
      accessCtrlCode += 'var SamlStrategy = require(\'passport-saml\').Strategy;\n'
      accessCtrlCode += '//ADFS example\n'
      accessCtrlCode += 'passport.use(new SamlStrategy(\n{\n'
      accessCtrlCode += 'entryPoint: \'https://adfs.acme_tools.com/adfs/ls/\',\n'
      accessCtrlCode += 'issuer: \'acme_tools_com\',\n'
      accessCtrlCode += 'callbackUrl: \'https://acme_tools.com/adfs/postResponse\',\n'
      accessCtrlCode += 'privateCert: fs.readFileSync(\'/path/to/acme_tools_com.key\', \'utf-8\'),\n'
      accessCtrlCode += 'cert: fs.readFileSync(\'/path/to/adfs.acme_tools.com.crt\', \'utf-8\'),\n'
      accessCtrlCode += '//other authn contexts are available e.g. windows single sign-on\n'
      accessCtrlCode += 'authnContext: \'http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/password\',\n'
      accessCtrlCode += 'acceptedClockSkewMs: -1,\n'
      accessCtrlCode += 'identifierFormat: null,\n'
      accessCtrlCode += ' // this is configured under the Advanced tab in AD FS relying party\n'
      accessCtrlCode += 'signatureAlgorithm: \'sha256\'\n},\n'
      accessCtrlCode += 'function(profile, done) {\n'
      accessCtrlCode += 'return done(null,\n{\n'
      accessCtrlCode += 'upn: profile[\'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn\'],\n'
      accessCtrlCode += ' // e.g. if you added a Group claim\n'
      accessCtrlCode += 'group: profile[\'http://schemas.xmlsoap.org/claims/Group\']\n});\n}\n));\n'
      accessCtrlCode += '//inside app.js\n'
      accessCtrlCode += 'app.post(\'/login/callback\',\n'
      accessCtrlCode += 'passport.authenticate(\'saml\', { failureRedirect: \'/\', failureFlash: true }),\n'
      accessCtrlCode += 'function(req, res) {\n'
      accessCtrlCode += 'res.redirect(\'/\');\n}\n);'
      accessCtrlCode += 'app.get(\'/login\',\n'
      accessCtrlCode += 'passport.authenticate(\'saml\', { failureRedirect: \'/\', failureFlash: true }),\n'
      accessCtrlCode += 'function(req, res) {\n res.redirect(\'/\');\n}\n);\n'
    }
    if ((p.accessControlsPolicy.authenticationPolicy.supportedMethods).includes('oauth')) {
      accessCtrlCode += 'var oauth2 = spawn(\'npm\', [\'install\', \'passport-oauth2\']);\n'
      accessCtrlCode += 'var OAuth2Strategy = require(\'passport-oauth2\').Strategy;\n'
      accessCtrlCode += 'passport.use(new OAuth2Strategy({\n'
      accessCtrlCode += 'authorizationURL: \'https://www.example.com/oauth2/authorize\',\n'
      accessCtrlCode += 'tokenURL: \'https://www.example.com/oauth2/token\',\n'
      accessCtrlCode += 'clientID: EXAMPLE_CLIENT_ID,\n'
      accessCtrlCode += 'clientSecret: EXAMPLE_CLIENT_SECRET,\n'
      accessCtrlCode += 'callbackURL: "http://localhost:3000/auth/example/callback"\n},\n'
      accessCtrlCode += 'function(accessToken, refreshToken, profile, cb) {\n'
      accessCtrlCode += 'User.findOrCreate({ exampleId: profile.id }, function (err, user) {\n'
      accessCtrlCode += 'return cb(err, user);\n});\n}\n));\n'
      accessCtrlCode += '//inside app.js\n'
      accessCtrlCode += 'app.get(\'/auth/example\', passport.authenticate(\'oauth2\'));\n'
      accessCtrlCode += 'app.get(\'/auth/example/callback\',\n'
      accessCtrlCode += 'passport.authenticate(\'oauth2\', { failureRedirect: \'/login\' }),\n'
      accessCtrlCode += 'function(req, res) {\n'
      accessCtrlCode += '// Successful authentication, redirect home.\n'
      accessCtrlCode += 'res.redirect(\'/\');\n});\n'
    }
    if ((p.accessControlsPolicy.authenticationPolicy.supportedMethods).includes('jwt')) {
      accessCtrlCode += 'var jwt = spawn(\'npm\', [\'install\', \'passport-jwt\']);\n'
      accessCtrlCode += 'var JwtStrategy = require(\'passport-jwt\').Strategy,\n'
      accessCtrlCode += '\tExtractJwt = require(\'passport-jwt\').ExtractJwt;\n'
      accessCtrlCode += 'var opts = {};\n'
      accessCtrlCode += 'opts.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken();\n'
      accessCtrlCode += 'opts.secretOrKey = \'secret\';'
      accessCtrlCode += 'opts.issuer = \'accounts.examplesoft.com\';\n'
      accessCtrlCode += 'opts.audience = \'yoursite.net\';\n'
      accessCtrlCode += 'passport.use(new JwtStrategy(opts, function(jwt_payload, done) {\n'
      accessCtrlCode += '\tUser.findOne({id: jwt_payload.sub}, function(err, user) {\n'
      accessCtrlCode += '\t\tif (err) {\n'
      accessCtrlCode += '\t\treturn done(err, false);\n}\n'
      accessCtrlCode += 'if (user) {\n'
      accessCtrlCode += 'return done(null, user);\n'
      accessCtrlCode += ' } else {\n'
      accessCtrlCode += 'return done(null, false);\n'
      accessCtrlCode += '  // or you could create a new account\n}\n});\n}));'
    }
    // else {
    //   console.log (`The method ${p.accessControlsPolicy.authenticationPolicy.supportedMethods} is not one of the supported methods.\n Access Control boilerplate code was not written\n`);
    // }
    return {
      'accessCtrlCode': accessCtrlCode,
      'accessCtrlMods': accessCtrlMods
    }
  } catch (e) {
    console.log(e)
  }
}
function connectBp (p) {
  try {
    var connectCode = ''
    var connectMods = []
    return {
      'connectCode': connectCode,
      'connectMods': connectMods
    }
  } catch (e) {
    console.log(e)
  }
}
function corsBp (p) {
  try {
    var corsCode = ''
    var corsMods = []
    if (p.resourceSharingPolicy.corsSettings.enabled) {
      corsCode += '/*-------------------------------------------CORS------------------------------------------------*/\n'
      corsCode += 'var corsWhitelist = secJson.resourceSharingPolicy.corsSettings.config.whitelist;\n'
      corsCode += '//need to iterate over the whitelist to find dynamic values (e.g. *.foo.bar.com)\n'
      corsCode += 'for (var w = 0; w < corsWhitelist.length; w++){\n\t'
      corsCode += 'if(corsWhitelist[w].search(\'*\')){\n'
      corsCode += '\t\t corsWhitelist[w].replace(/`*`/g, `/\\.`);\n\t}\n}\n'
      corsCode += 'var corsOptions;\n'
      corsCode += '/* Here we need to distinguish between non-senstive and sensitive operations; anyone can make a GET request;\n otherwise, the more sensitive the operation (PUT, POST, PATCH), the more stringent the whitelist. As an example, mysite.foo.bar should be able to make a GET \n request...I don\'t need to whitelist that out because it\'s a non-sensitive operation (with some conditions, like credentials) \n however we DO need to put HTTPS://mysite.foo.bar:8080 on our whitelist if we\'re going allow it to make changes to our server. FOR THAT REASON, I would HIGHLY recommend NOT allowing ALL subdomains of a host on your whitelist, \nbut rather a few, very specific routes on a host*/\n'
      corsCode += 'if (corsWhitelist === []){\n'
      corsCode += '\t corsOptions = {\n'
      corsCode += '\t\t origin: \'*\',\n'
      corsCode += '\t\t methods : \'GET,OPTIONS\',\n'
      corsCode += '\t\t credentials : true,\n'
      corsCode += '\t\t preflightContinue : true,\n'
      corsCode += '\t\t optionsSuccessStatus: 200\n\t}\n}'
      corsCode += '\t else {\n'
      corsCode += '\tcorsOptions = {\n'
      corsCode += '\t\torigin : function (origin, cb){\n'
      corsCode += '\t//check to see if origin is on the whitelist\n'
      corsCode += '\t\t if(whitelist.includes(origin)){\n'
      corsCode += '\t\t\t cb(null, true);'
      corsCode += '\n\t\t} else {\n'
      corsCode += '\t\t\t cb (new Error (\'Not allowed by CORS\'));\n}\n},\n'
      corsCode += '\t\t methods: [\'GET\', \'POST\', \'PUT\', \'PATCH\', \'DELETE\', \'OPTIONS\'],\n'
      // corsCode += '\t\t allowedHeaders : []\n';
      corsCode += '\t\t credentials : true,\n'
      corsCode += '\t\t maxAge : secJson.resourceSharingPolicy.corsSettings.config.preflightRequests.maxAge,\n'
      corsCode += '\t\t preflightContinue : true,\n'
      corsCode += '\t\t optionsSuccessStatus : 200\n}\n}'
      corsCode += '//-------------------pre-flighting: add options handler ahead of your other unsafe methods-------------*/\n'
      corsCode += 'app.options(\'*\', cors()); // enable pre-flight request for all routes & methods across the board\n'
      corsCode += 'module.exports.corsOptions = corsOptions;\n'
    } else {
      corsCode += '\n\t\t\t\t//no CORS policy configured\n\n\n'
    }
    return {
      'corsCode': corsCode,
      'corsMods': corsMods
    }
  } catch (e) {
    console.log(e)
  }
}
function logBp (p) {
  try {
    var logCode = ''
    var logMods = []
    if (p.loggingPolicy.enabled) {
      // Create the log directory if it does not exist
      // if (!fs.existsSync(p.loggingPolicy.logCollection.storage)) {
      //   fs.mkdirSync(`./security/${p.applicationName}/logs/`);
      // }
      logCode += '/*-------------------------------------Logging---------------------------------*/\n'
      logCode += 'const tsFormat = () => (new Date()).toLocaleTimeString();\n'
      // logCode += 'const p = require(\'./security.json\');\n\n';
      logCode += 'if (p.loggingPolicy.levelsSupported === \'custom\') const levels = { levels : secJson.loggingPolicy.levels};\n'
      logCode += 'var options = { \nfile: {\n'
      logCode += '\tlevel: \'info\',\n'
      logCode += '\tfilename: secJson.loggingPolicy.logCollection.storage,\n'
      logCode += '\ttimestamp : tsFormat,\n'
      logCode += '\thandleExceptions: true,\n'
      logCode += '\tjson: true,\n'
      logCode += '\tmaxsize: 5242880, // 5MB\n'
      logCode += '\tmaxFiles: 5,\n'
      logCode += '\tcolorize: true,\n},\n'
      logCode += 'console: {\n'
      logCode += '\tlevel: \'debug\',\n'
      logCode += '\thandleExceptions: true,\n'
      logCode += '\ttimestamp : tsFormat,\n'
      logCode += '\tjson: true,\n'
      logCode += '\tcolorize: true,\n },\n};\n\n'
      logCode += 'const logger = winston.createLogger({\n'
      logCode += '\tlevels : levels.levels,\n'
      logCode += '\ttransports: [ new winston.transports.File(options.file), \n\t\t\t\tnew winston.transports.Console(options.console)],\n'
      logCode += '\texitOnError: false // do not exit on handled exceptions\n});\n'
      logCode += 'module.exports.logger = logger;'
    } else {
      logCode = '//no log policy configured\n'
    }
    return {
      'logCode': logCode,
      'logMods': logMods
    }
  } catch (e) {
    console.log('could not write logging policy', e)
  }
}
async function interpreter (p, mods) {
  try {
    var finalCode = ''
    const appDepData = await appDepBp(p)
    finalCode += appDepData.appDepCode
    const accessCtrlData = await accessCtrlBp(p)
    finalCode += accessCtrlData.accessCtrlCode
    const connectData = await connectBp(p)
    finalCode += connectData.connectCode
    const corsData = await corsBp(p)
    finalCode += corsData.corsCode
    const logging = await logBp(p)
    finalCode += logging.logCode
    // mods.push(logging.logMods);
    var allMods = []
    for (var m = 0; m < mods.length; m++) {
      allMods[m] = `var ${mods[m]} = require('${mods[m]}');\n`
    }
    return {
      'allModules': allMods,
      'finalCode': finalCode
    }
  } catch (e) {
    console.log(chalk.yellow(`There was a problem interpreting the policy and boilerplate code could not be written, ${e}`))
  }
}

function wbp (code, pathToFile) {
  var wbp = fs.createWriteStream(pathToFile, { flag: 'wx' })
  var convert = '\'use strict\';\n'
  wbp.write(convert)
  for (var c = 0; c < (code.allModules).length; c++) {
    wbp.write(code.allModules[c])
  }
  wbp.write('var secJson = require(\'./security.json\') //may need to adjust this to the actual location of your policy file\n')
  wbp.write(code.finalCode)
  wbp.close()
}

async function writeBoilerplate (policy) {
  try {
    var modules = []
    if (policy.appDependencies.enabled) modules.push('snyk')
    if (policy.accessControlsPolicy.enabled && policy.accessControlsPolicy.authenticationPolicy.authenticationRequired) {
      modules.push('passport')
      modules.push('bcrypt')
    }
    if (policy.accessControlsPolicy.enabled && policy.accessControlsPolicy.authorization.authorizationRequired) {
      modules.push('rbac')
    }
    if (policy.sessionPolicy.enabled) {
      modules.push('mongodb')
      modules.push('js-cookie')
      modules.push('csurf')
    }
    if (policy.formProtection.enabled) modules.push('forms')
    if (policy.securityHeaders.enabled) {
      modules.push('helmet')
      modules.push('mime-types')
    }
    if (policy.securityHeaders.enabled && policy.securityHeaders.caching.enabled) modules.push('redis')
    if (policy.contentValidationPolicy.enabled) {
      modules.push('validator')
      modules.push('joi')
    }
    // if(policy.dbSecurityPolicy.enabled){
    //
    // }
    // if(policy.connectionPolicy.enabled){
    //
    // }
    if (policy.resourceSharingPolicy.corsSettings.enabled) {
      modules.push('cors')
    }
    if (policy.loggingPolicy.enabled) {
      modules.push('winston')
    }
    var bpCode = await interpreter(policy, modules)
    // installModules(modules);
    wbp(bpCode, pathToBoilerPlate)
    var msg = chalk.magenta(`Successfully wrote boilerplate code for policy ${policy.policyId}\n`)
    return {
      'modules': modules,
      'message': msg,
      'pathToFile': pathToBoilerPlate }
  } catch (e) {
    throw e
  }
}
module.exports.matches = matches
module.exports.diff = diff
module.exports.writeBoilerplate = writeBoilerplate
module.exports.removeModules = removeModules
