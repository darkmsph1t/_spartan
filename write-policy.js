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

function writePolicy(input) {
  var secJson = fs.createWriteStream("./security.json"); // <- create security.json
  var tmp = JSON.parse(fs.readFileSync("security-default.json")); // <- open the default file
  tmp._policyId = uniqid(); // <- create & populate a policy id
  try {
      var pkg = fs.readFileSync("package.json"); //check to see if package.json exists & read
      var pkgJson = JSON.parse(pkg); // <- parse package.json and pass to an object
      tmp.applicationName = pkgJson.name; // <- add application name to the policy
  } catch (err){
    console.log("Could not find package.json file. Please run 'npm init' and build package.json first\n"); // <- if unable to find the package.json file, return an error
    console.log (err.code + " : " + err.path);
  }
  /* now that I have the tmp object I need to be able to:
  1. Identify the appropriate changes in security.json based upon the answers provided from the questionnaire (passed in as the object 'input')
  2. Look up the applicable keys  and change the corresponding value to match what makes sense for the (presumably something like: for (const key in tmp) {if key == 'blah', change tmp[key] to 'blah blah'})
  3. Write the whole thing to security.json **remember: tmp is STILL a JSON object, so there's no need to convert the whole thing to JSON. It MIGHT be worthwhile to convert it to a string using JSON.stringify(tmp)**
  4. Close the stream
  */
try {  //Administrative Stuff
    tmp.applicationType = input.type;
    tmp.internetFacing = input.exposure;
    if (input.hostname){
      tmp.hostname = input.hostname;
    } else {
      tmp.hostname = "none";
    }
    //App Dependencies
    if (!input.exposure){
      tmp.appDependencies = removeSection(tmp.appDependencies);
    }
    //Access Controls
    if(!input.access){
      tmp.accessControlsPolicy = removeSection(tmp.accessControlsPolicy);
    } else {
      sbAccess(input, tmp);
    }

    //Session Management
    if (input.sessions !== "User sessions have a set timeout"){
      tmp.sessionPolicy = removeSection(tmp.sessionPolicy)
    } else {
      sbSessions(input, tmp);
    }
    //Connection Security
    if(!input.secureTransport){
      tmp.connectionPolicy = removeSection(tmp.connectionPolicy);
      setValue(tmp.securityHeaders, "directives", "blockAllMixedContent", false);
      setValue(tmp.securityHeaders, "directives", "upgradeInsecureRequests", false);
      setValue(tmp.securityHeaders, "config", "strictTransportSecurity", {});
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
      setValue(tmp.resourceSharingPolicy, "corsSettings", "config", {});
    } else {
      sbCors(input, tmp);
    }
    //Form Protection
    if (!input.forms) {
      tmp.formProtection = removeSection(tmp.formProtection);
      setValue(tmp.securityHeaders, "sandbox", "allowForms", false);
    } else {
      sbForms(input, tmp);
    }
    //Caching Strategy
    if (!input.cacheStrategy){
      tmp.securityHeaders.caching = removeSection(tmp.securityHeaders.caching);
    } else {
      sbCache(input, tmp);
    }
    //Logging Policy
    if (input.logging){
      setValue(tmp.loggingPolicy, "logCollection", "storage", input.logging);
    } else {
      var logs = "/var/log"+tmp.appName+"/";
      setValue(tmp.loggingPolicy, "logCollection", "storage", logs);
    }
    tmp.deployment = input.deployment;
    var convert = JSON.stringify(tmp,null, "  ");
    secJson.write(convert);
    secJson.close();
  } catch (e){
    console.log("Something went terribly wrong : " + e);
  }
}
module.exports.writePolicy = writePolicy;
