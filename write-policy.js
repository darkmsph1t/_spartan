'use strict';
var fs = require("fs");
var uniqid = require('uniqid');

function toObj(object){
  const result = {};
  for (const prop in object){
    if (typeof object[prop] == "object"){
      result[prop] = toObj(object[prop]);
    } else {
      result[prop] = object[prop];
    }
  }
  return result;
}

function toArray(object) {
    const result = [];
    for (const prop in obj) {
        const value = obj[prop];
        if (typeof value == 'object') {
            result.push(toArray(value)); // <- recursive call
        }
        else {
            result.push(value);
        }
    }
    return result;
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
  //secJson.write("{\n");
  /* now that I have the tmp object I need to be able to:
  1. Identify the appropriate changes in security.json based upon the answers provided from the questionnaire (passed in as the object 'input')
  2. Look up the applicable keys  and change the corresponding value to match what makes sense for the (presumably something like: for (const key in tmp) {if key == 'blah', change tmp[key] to 'blah blah'})
  3. Write the whole thing to security.json **remember: tmp is STILL a JSON object, so there's no need to convert the whole thing to JSON. It MIGHT be worthwhile to convert it to a string using JSON.stringify(tmp)**
  4. Close the stream
  */
  if(input.exposure){
    //change some things in tmp based on this value being true;
  } else {

  }
  if (input.access) {
    //change some things in tmp based on this value being true;
  }
  if (input.sessions){
    //change some things in tmp based on this value being true;
    tmp.sessionPolicy.duration.ttl = (input.sessionLength)*1000;
  } else {
    var rem = toObj(tmp.sessionPolicy);

    for (const keys in rem){
      if (keys !== "enabled" && keys !== "compensatingControl"){
        //remove the element at keys
        console.log(Object.keys(rem[keys]))
        //save the new object to tmp.sessionPolicy
        //tmp.sessionPolicy[keys] = rem[keys];
        tmp.sessionPolicy.enabled = false;
        tmp.sessionPolicy.compensatingControl = "unknown";
      }
    }

  }
  // console.log ("here is your security policy: \n");
  // console.log(tmp);
  // console.log("\n the policy has been saved at: ");
  //secJson.write("\n}");
  //secJson.end();
}
//writePolicy();

module.exports.writePolicy = writePolicy;
