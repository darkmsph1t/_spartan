'use strict';
var fs = require("fs");
var uniqid = require('uniqid');

function sbAccess(obj, tmp){
  if (obj.exposure){
    //Access Controls
    setValue(tmp.accessControlsPolicy, "passwords", "minLen", 12);
    setValue(tmp.accessControlsPolicy, "passwords", "attempts", 3);
    setValue(tmp.accessControlsPolicy, "authenticationPolicy", "mfaRequired", true);
    setValue(tmp.accessControlsPolicy, "lockout", "tarpitDefault", (5*60*1000));
    setValue(tmp.accessControlsPolicy, "authorization", "authorizationRequired", true);
    setValue(tmp.accessControlsPolicy, "rbacPolicy", "roles", ["user", "admin"]);
  } else {
    setValue(tmp.accessControlsPolicy, "passwords", "minLen", 8);
    setValue(tmp.accessControlsPolicy, "passwords", "attempts", 5);
    setValue(tmp.accessControlsPolicy, "authenticationPolicy", "mfaRequired", false);
    setValue(tmp.accessControlsPolicy, "passwords", "expires", 7776000);
    setValue(tmp.accessControlsPolicy, "authorization", "authorizationRequired", true);
    setValue(tmp.accessControlsPolicy, "rbacPolicy", "roles", ["user", "admin"]);
  }
}

function sbForms(obj, tmp){
  setValue(tmp.formProtection, "config", "autocompleteAllowed", false);
  setValue(tmp.formProtection, "config", "acceptJsonContent", true);
  setValue(tmp.formProtection, "config", "allowMethodOverride", false);
}

function sbSessions(obj, tmp){
  if (obj.exposure){
    if(!obj.access && obj.type == 'Web' || !obj.access && obj.type == 'API'){
      console.log("Access Control Policy cannot be disabled for this application type and exposure")
      sbAccess(obj, tmp);
    }
    //idle time
    if(obj.type == 'Desktop'){
      setValue(tmp.sessionPolicy, "duration", "idle", (15*60));
    }
    else if (obj.type == 'Web' || obj.type == 'Mobile'){ setValue(tmp.sessionPolicy, "duration", "idle", (5*60))}
    else if (obj.type == 'Kiosk'){setValue(tmp.sessionPolicy, "duration", "idle", (2*60))}
    else { setValue(tmp.sessionPolicy, "duration", "idle", (1*60))}

  } else {
    //id
    setValue(tmp.sessionPolicy, "id", "length", 64);
    //TTL
    setValue(tmp.sessionPolicy, "duration", "ttl", (60*60));
    //idle time
    if(obj.type == 'Desktop' || obj.type == 'Web' || obj.type == 'Mobile'){ setValue(tmp.sessionPolicy, "duration", "idle", (15*60));}
    else if (obj.type == 'Kiosk'){setValue(tmp.sessionPolicy, "duration", "idle", (5*60));}
    else { setValue(tmp.sessionPolicy, "duration", "idle", (2*60));}
    //cookies
    setValue(tmp.sessionPolicy, "cookies", "httpOnly", false);
    setValue(tmp.sessionPolicy, "cookies", "secure", false);
    setValue(tmp.sessionPolicy, "cookies", "sameSite", false);

    //automatic automaticRenewal
    if(obj.type == 'Desktop'){
      setValue(tmp.sessionPolicy, "duration", "automaticRenewal", true);
    }
    //csrfSettings
    setValue(tmp.sessionPolicy, "csrfSettings", "secretLength", 64);
  }
  setValue(tmp.sessionPolicy, "duration", "ttl", obj.sessionLength);
  setValue(tmp.sessionPolicy, "cookies", "maxAge", (obj.sessionLength * 1000));
}
function sbConnections(obj, tmp){
  //if the app is internal do this
  // otherwise if the app is external do this
}

function sbCors(obj, tmp){
  //securityHeaders first
  if(obj.type == "Embedded/IoT (Controller)" || obj.type == "API"){
    var zing = tmp.securityHeaders.config.csp.directives;
    for (var h in zing){
      if (h == 'default' || h == 'upgradeInsecureRequests' || h == 'blockAllMixedContent' ||
          h == 'subResourceIntegrity'){
        //skip
      }
      else {
        delete zing[h];
      }
    }
    setValue(tmp.securityHeaders, "directives", "default", "none");
  } else {
    for(var k in obj.contentSources){
      setValue(tmp.securityHeaders, "directives", k, obj.contentSources[k]);
    }
  }
  //cors next
  if(obj.type == "Embedded/IoT (Controller)" || obj.type == "API"){
    setValue(tmp.resourceSharingPolicy, "corsSettings", "config", {});
  }
  else {
    const result = [];
    for(var j in obj.contentSources){
      var bloop = Object.values(obj.contentSources[j]);
      for (var i = 0; i <= bloop.length; i++){
        if ( bloop[i] == "self" || bloop[i] == "none" || bloop[i] == null){
          // console.log("found : " + bloop[i]);
        } else {
          result.push(bloop[i]);
        }
      }
    }
    setValue(tmp.resourceSharingPolicy, "corsSettings", "enabled", true);
    setValue(tmp.resourceSharingPolicy, "config", "whitelist", result);
  }
}
function sbCache(obj, tmp){
  var cache = tmp.securityHeaders.caching.cacheControl;
  if (!obj.exposure){
    if (obj.type == 'Desktop' || obj.type == 'Mobile'){
      setValue(tmp.securityHeaders, "caching", "cacheControl", ["private", "max-age=2592000"]);
      setValue(tmp.securityHeaders, "caching", "pragma", "private");
    } else if (obj.type == 'Web'){
      setValue(tmp.securityHeaders, "caching", "cacheControl", ["private", "max-age=1296000"]);
      setValue(tmp.securityHeaders, "caching", "pragma", "private");
    } else {
      setValue(tmp.securityHeaders, "caching", "cacheControl", ["no-cache", "no-store", "no-transform", "must-revalidate", "max-age=0"]);
    }
    setValue(tmp.securityHeaders, "eTags", "strength", "weak");
    setValue(tmp.securityHeaders, "caching", "vary", "none");
  }
}

function removeSection(section){
  section = {};
  section.enabled = false;
  section.compensatingControl = "unknown";
  return section;
}

function addSection(section, key, value){
    section[key] = value;
}

function setValue(obj, key, subkey, value){
  for (var k in obj){
    if (k !== key){
      if (typeof obj[k] == 'object'){
        setValue(obj[k], key, subkey, value);
      } else {
        //console.log("value of " + obj[k] + " is not an object");
      }
    } else {
        for (var j in obj[k]){
          if (j == subkey){
            obj[k][j] = value;
            //console.log(obj[k][j]);
          }
        }
      }
    }
  return obj;
}

function writePolicy(input = {}, opt = "init") {
  var pkg = fs.readFileSync("./package.json");
  var pkgJson = JSON.parse(pkg);

  if (opt == "init"){
    var secJson = fs.createWriteStream("./security/security.json"); // <- create security.json
    var tmp = JSON.parse(fs.readFileSync("./security/security-default.json")); // <- open the default file
    // 1. Identify the appropriate changes in security.json based upon the answers provided from the questionnaire (passed in as the object 'input')
    tmp._policyId = uniqid(); // <- create & populate a policy id
    try {
        // var pkg = fs.readFileSync("package.json"); //check to see if package.json exists & read
        // var pkgJson = JSON.parse(pkg); // <- parse package.json and pass to an object
        tmp.applicationName = pkgJson.name; // <- add application name to the policy
    } catch (err){
      console.log("Could not find package.json file. Please run 'npm init' and build package.json first\n"); // <- if unable to find the package.json file, return an error
      console.log (err.code + " : " + err.path);
    }

    // 2. Look up the applicable keys and change the corresponding value to match
    try {
          //Administrative Stuff
          tmp.applicationType = input.type;
          tmp.internetFacing = input.exposure;
          if (input.hostname){
            tmp.hostname = input.hostname;
          } else {
            tmp.hostname = "localhost";
          }
          //App Dependencies
          if (!input.exposure){
            addSection(tmp.appDependencies, "enabled", false);
            addSection(tmp.appDependencies, "compensatingControl", "unknown");
            addSection(tmp.appDependencies, "auditOptions", []);
            addSection(tmp.appDependencies, "autoFix", null);
            addSection(tmp.appDependencies, "pathToReport", null);
          }
          //Access Controls
          if(!input.access){
            addSection(tmp.accessControlsPolicy, "enabled", false);
            addSection(tmp.accessControlsPolicy, "compensatingControl", "unknown");
            addSection(tmp.accessControlsPolicy, "authenticationPolicy", {});
            addSection(tmp.accessControlsPolicy.authenticationPolicy, "authenticationRequired", false);
            addSection(tmp.accessControlsPolicy.authenticationPolicy, "supportedMethods", []);
            addSection(tmp.accessControlsPolicy.authenticationPolicy, "passwords", {});
            addSection(tmp.accessControlsPolicy.authenticationPolicy.passwords, "minLength", null);
            addSection(tmp.accessControlsPolicy.authenticationPolicy.passwords, "expires", null);
            addSection(tmp.accessControlsPolicy.authenticationPolicy.passwords, "supportedHashes", []);
            addSection(tmp.accessControlsPolicy.authenticationPolicy.passwords, "lockout", {});
            addSection(tmp.accessControlsPolicy.authenticationPolicy.passwords.lockout, "attempts", null);
            addSection(tmp.accessControlsPolicy.authenticationPolicy.passwords.lockout, "automaticReset", null);
            addSection(tmp.accessControlsPolicy.authenticationPolicy.passwords.lockout, "tarpitDefault", null);
            addSection(tmp.accessControlsPolicy.authenticationPolicy, "mfaRequired", null);
            addSection(tmp.accessControlsPolicy, "authorization", {});
            addSection(tmp.accessControlsPolicy.authorization, "authorizationRequired", false);
            addSection(tmp.accessControlsPolicy.authorization, "supportedTypes", []);
            addSection(tmp.accessControlsPolicy.authorization, "rbacPolicy", {});
            addSection(tmp.accessControlsPolicy.authorization.rbacPolicy, "roles", []);
            addSection(tmp.accessControlsPolicy.authorization.rbacPolicy, "permissions", []);
            //tmp.accessControlsPolicy = removeSection(tmp.accessControlsPolicy);
          } else {
            sbAccess(input, tmp);
          }

          //Session Management
          if (input.sessions !== "User sessions have a set timeout"){
            addSection(tmp.sessionPolicy, "enabled", false);
            addSection(tmp.sessionPolicy, "compensatingControl", "unknown");
            addSection(tmp.sessionPolicy, "config", {});
            addSection(tmp.sessionPolicy.config, "id", {});
            addSection(tmp.sessionPolicy.config.id, "length", null);
            addSection(tmp.sessionPolicy.config.id, "entropy", null);
            addSection(tmp.sessionPolicy.config.id, "invalidOnLogout", null);
            addSection(tmp.sessionPolicy.config.id, "regenerateOnAuth", null);
            addSection(tmp.sessionPolicy.config.id, "forceLogoutOnWindowClose", null);
            addSection(tmp.sessionPolicy.config, "duration", {});
            addSection(tmp.sessionPolicy.config.duration, "idle", null);
            addSection(tmp.sessionPolicy.config.duration, "ttl", null);
            addSection(tmp.sessionPolicy.config.duration, "automaticRenewal", null);
            addSection(tmp.sessionPolicy.config, "cookies", {});
            addSection(tmp.sessionPolicy.config.cookies, "prefixes", []);
            addSection(tmp.sessionPolicy.config.cookies, "maxAge", null);
            addSection(tmp.sessionPolicy.config.cookies, "httpOnly", null);
            addSection(tmp.sessionPolicy.config.cookies, "secure", null);
            addSection(tmp.sessionPolicy.config.cookies, "sameSite", null);
            addSection(tmp.sessionPolicy.config.cookies, "domain", null);
            addSection(tmp.sessionPolicy.config.cookies, "path", null);
            addSection(tmp.sessionPolicy.config, "csrfSettings", {});
            addSection(tmp.sessionPolicy.config.csrfSettings, "secretLength", null);
            addSection(tmp.sessionPolicy.config.csrfSettings, "saltLength", null);
            addSection(tmp.sessionPolicy.config.csrfSettings, "ignoreMethods", []);
            addSection(tmp.sessionPolicy.config.csrfSettings, "allowHiddenToken", null);
            addSection(tmp.sessionPolicy.config.csrfSettings, "validateToken", null);
            addSection(tmp.sessionPolicy.config, "concurrentLogins", null);
            //tmp.sessionPolicy = removeSection(tmp.sessionPolicy)
          } else {
            sbSessions(input, tmp);
          }
          //Connection Security
          if(!input.secureTransport){
            //tmp.connectionPolicy = removeSection(tmp.connectionPolicy);
            addSection(tmp.connectionPolicy, "enabled", false);
            addSection(tmp.connectionPolicy, "compensatingControl", "unknown");
            addSection(tmp.connectionPolicy, "redirectSecure", null);
            addSection(tmp.connectionPolicy, "rejectWeakCiphers", null);
            addSection(tmp.connectionPolicy, "rejectInsecureTLS", null);
            addSection(tmp.connectionPolicy, "forceHttps", false);
            setValue(tmp.securityHeaders, "directives", "blockAllMixedContent", false);
            setValue(tmp.securityHeaders, "directives", "upgradeInsecureRequests", false);
            setValue(tmp.securityHeaders, "config", "strictTransportSecurity", {});
            addSection(tmp.securityHeaders.config.strictTransportSecurity, "enabled", false);
            addSection(tmp.securityHeaders.config.strictTransportSecurity, "includeSubDomains", null);
            addSection(tmp.securityHeaders.config.strictTransportSecurity, "preload", null);
            addSection(tmp.securityHeaders.config.strictTransportSecurity, "maxAge", null);
          } else {
            //tmp.connectionPolicy = sbConnections(input, tmp);
          }
          //Content Security
          if(input.content == "All of the data and content comes from sources that I own or control"){
            setValue(tmp.securityHeaders, "directives", "default", ["self"]);
            setValue(tmp.securityHeaders, "directives", "media", ["self"]);
            setValue(tmp.securityHeaders, "directives", "images", ["self"]);
            setValue(tmp.securityHeaders, "directives", "fonts", ["self"]);
            setValue(tmp.securityHeaders, "directives", "media", ["self"]);
            setValue(tmp.securityHeaders, "directives", "frame-ancestors", ["self"]);
            setValue(tmp.securityHeaders, "directives", "child-sources", ["none"]);
            setValue(tmp.resourceSharingPolicy, "corsSettings", "enabled", false);
            addSection(tmp.resourceSharingPolicy.corsSettings.config, "whitelist", ["same-origin"]);
            addSection(tmp.resourceSharingPolicy.corsSettings.config, "preflightRequests", {});
            addSection(tmp.resourceSharingPolicy.corsSettings.config.preflightRequests, "onMethod", []);
            addSection(tmp.resourceSharingPolicy.corsSettings.config.preflightRequests, "onHeader", []);
            addSection(tmp.resourceSharingPolicy.corsSettings.config.preflightRequests, "maxAge", null);
            addSection(tmp.resourceSharingPolicy.corsSettings.config, "responseHeaders", {});
            addSection(tmp.resourceSharingPolicy.corsSettings.config.responseHeaders, "allowCredentials", null);
            addSection(tmp.resourceSharingPolicy.corsSettings.config.responseHeaders, "validateHeaders", null);
          } else {
            sbCors(input, tmp);
          }
          //Form Protection
          if (!input.forms) {
            //tmp.formProtection = removeSection(tmp.formProtection);
            addSection(tmp.formProtection, "enable", false);
            addSection(tmp.formProtection, "compensatingControl", "unknown");
            addSection(tmp.formProtection, "config", {});
            addSection(tmp.formProtection.config, "autocompleteAllowed", null);
            addSection(tmp.formProtection.config, "acceptJsonContent", null);
            addSection(tmp.formProtection.config, "allowMethodOverride", null);
            setValue(tmp.securityHeaders, "sandbox", "allowForms", false);
          } else {
            sbForms(input, tmp);
          }
          //Caching Strategy
          if (!input.cacheStrategy){
            addSection(tmp.securityHeaders.caching, "enabled", false);
            addSection(tmp.securityHeaders.caching, "compensatingControl", "unknown");
            addSection(tmp.securityHeaders.caching, "routeOverload", null);
            addSection(tmp.securityHeaders.caching, "cacheControl", []);
            addSection(tmp.securityHeaders.caching, "pragma", null);
            addSection(tmp.securityHeaders.caching, "eTags", {});
            addSection(tmp.securityHeaders.caching.eTags, "enabled", false);
            addSection(tmp.securityHeaders.caching.eTags, "strength", null);
            addSection(tmp.securityHeaders.caching, "vary", []);
            //tmp.securityHeaders.caching = removeSection(tmp.securityHeaders.caching);
          } else {
            sbCache(input, tmp);
          }
          //Logging Policy
          if (input.logging){
            setValue(tmp.loggingPolicy, "logCollection", "storage","/var/log/"+tmp.applicationName+"/");
          } else {
            var logs = input.logging;
            setValue(tmp.loggingPolicy, "logCollection", "storage", logs);
          }
          tmp.deployment = input.deployment;
          // 3. Write the whole thing to security.json **remember: tmp is STILL a JSON object, so there's no need to convert the whole thing to JSON. It MIGHT be worthwhile to convert it to a string using JSON.stringify(tmp)
          var convert = JSON.stringify(tmp,null, "  ");
          secJson.write(convert);
          //  4. Close the stream
          secJson.close();
      } catch (e){
        console.log("Something went terribly wrong : " + e);
      }
    } else if (opt == "default"){
        var secJson = fs.createWriteStream("./security/security.json");
        var tmp = JSON.parse(fs.readFileSync("./security/security-default.json"));
        tmp._policyId = uniqid();
        try {
            tmp.applicationName = pkgJson.name;
            tmp.applicationType = "Not Specified";
            tmp.internetFacing = true;
        } catch (err){
          console.log("Could not find package.json file. Please run 'npm init' and build package.json first\n");
          console.log (err.code + " : " + err.path);
        }
        var convert = JSON.stringify(tmp,null, "  ");
        secJson.write(convert);
        secJson.close();
    } else {
      console.error("Option: " + opt + " is not an available choice.");
    }
}
module.exports.writePolicy = writePolicy;
