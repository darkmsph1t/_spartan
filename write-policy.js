'use strict';
var fs = require("fs");
var uniqid = require('uniqid');


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
// function toObj(object){
//   const result = {};
//   for (const prop in object){
//     if (typeof object[prop] == "object"){
//       result[prop] = toObj(object[prop]);
//     } else if (typeof object[prop] == "array"){
//       result[prop] = toArray(object[prop]);
//     } else {
//       result[prop] = object[prop];
//     }
//   }
//   return result;
// }
//
// function toArray(object) {
//     const result = [];
//     for (const prop in obj) {
//         const value = obj[prop];
//         if (typeof value == 'array') {
//             result.push(toArray(value)); // <- recursive call
//         } else if (typeof value == 'object'){
//           result.push(toObj(value));
//         }
//         else {
//             result.push(value);
//         }
//     }
//     return result;
// }

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
  tmp.applicationType = input.type;
  tmp.appExposure = input.exposure;
  if (input.hostname){
    tmp.hostname = input.hostname;
  } else {
    tmp.hostname = "none";
  }

  if(!input.access){
    tmp.accessControlsPolicy = removeSection(tmp.accessControlsPolicy);
  }
  if (!input.forms) {
    tmp.formProtection = removeSection(tmp.formProtection);
    setValue(tmp.securityHeaders, "sandbox", "allowForms", false);
  }
  var convert = JSON.stringify(tmp,null, "  ");
  secJson.write(convert);
  secJson.close();
}
module.exports.writePolicy = writePolicy;
