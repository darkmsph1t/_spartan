'use strict';
var chalk = require('chalk');
var uniqid = require('uniqid');
var t = require('./transpose.js');
var fs = require('fs');
var path = require('path');
const uniqueString = require('unique-string');
var pkgJson = require('./package.json');
var pathToDefault = path.resolve('./security-default.json');

  /* POLICY METADATA INFO (IDs, STRUCTURE) */
function keyCount(p){
  try {
    var count;
    for(var i = 0; i < Object.keys(p).length; i++){
      if (p[i] === 'object'){
        count += 1;
        keyCount(p[i]);
      } else {
        count += 1;
      }
    }
    return count;
  } catch (e){
    console.log ('didn\'t make it');
  }
}

function  compare (pid1, pid2){
  if (pid1 === pid2){
    return true
  } else {
    return false
  }
}

function setPolicyId (policy){
  return policy["policyId"] = uniqueString();
}
function getPolicyId(){
  return read('./security.json').policyId;
}
function uniqueId (policy){
  var ids = Object.keys(audits);
  for (var i = 0; i < ids.length; i ++){
    if (policy.policyId === ids[i]){
      //the id has already been used and we need to set another one
      policy.policyId = setPolicyId(policy);
    }
  }
  return policy.policyId;
}
// function transpose (a, p){
//   /* Now I should have a default policy with a new ID and a name*/
//   return p
// }
function strip (p){
  p.policyId = '';
  p.applicationName = '';
  p.applicationType = '';
  p.internetFacing = '';
  return p
}

function wp (p, pathToPolicy){
  var wp = fs.createWriteStream(pathToPolicy);
  var convert = JSON.stringify(p, null, '  ');
  wp.write(convert);
  wp.close();
}
/* POLICY CRUD (CREATE, READ, UPDATE, DELETE)*/
function create(method, answers = {}) {
  try {
    var policy = read(pathToDefault);
    var pathToPolicy;
    if (answers.appName === 'Get this from package.json file'){
      policy.applicationName = pkgJson.name;
    } else {
      policy.applicationName = answers.appName;
    }
    policy.policyId = uniqueString();
    if (method === 'default'){
      pathToPolicy = './security.json';
      policy.applicationType = 'Web';
      policy.internetFacing = true;
      wp(policy, pathToPolicy);
    } else if (method === 'no-overwrite'){
      pathToPolicy = 'security-' + (policy.policyId).match(/.{1,8}/g)[3] + '.json';
      var o = t.transformer(answers, policy)
      wp(o, pathToPolicy);
    } else {
      pathToPolicy = './security.json';
      console.log ('Writing policy for ' + policy.applicationName + '\n');
      var p = t.transformer(answers, policy);
      wp(p, pathToPolicy);
    }
    /* a whole bunch of stuff to translate the answers into the final policy */
    var msg = chalk.magenta(`Congrats! The policy was successfully created at: ${path.resolve(pathToPolicy)}\n`);
    return [policy, msg, path.resolve(pathToPolicy)];
  } catch (e) {
    console.log('Something went wrong creating the policy ' + e);
  }
}

function read(pathToRead) {
  try {
    var pathToPolicy = path.resolve(pathToRead);
    var m = JSON.parse(fs.readFileSync(pathToPolicy));
    return m;
  } catch (e) {
    console.log(e);
  }
}

function update(newAnswers) {
  try{
    var oldPolicy = read('./security.json');
    var newPolicy = t.transformer(newAnswers, oldPolicy);
    if (compare(oldPolicy.policyId, newPolicy.policyId) === false) {
      throw new Error ('The policy did not update correctly. Please try again');
    } else {
      wp(newPolicy, './security.json');
      var message = 'The policy ' + newPolicy.policyId + ' was updated.';
      return [newPolicy, message];
    }
  } catch (e){
    console.log('There was a problem updating policy ' + oldPolicy.policyId + '\n' + e.code, e.path);
  }
}

function deletePolicy() {
  try {
    var pathToPolicy = path.resolve('./security.json');
    var pathToBoilerPlate = path.resolve('./security.js');
    var m = JSON.parse(fs.readFileSync(pathToPolicy));
    var policyNumber = m.policyId;
    fs.unlink(pathToBoilerPlate, function (err){
      if (err) { throw new Error (err) } else {
        //do some stuff to record the error
      }
    });
    fs.unlink(pathToPolicy, function (err){
      if (err) {  throw new Error (err);} else {
        //do some stuff to record the deletion in a file
      }
    });
    var msg = chalk.magenta(`All artifacts related to policy ${policyNumber} have been removed from the file system.\n`);
    console.log(msg);
    return msg;
  } catch (e){
    console.log(policyNumber + 'deleted\n' + e);
  }
}

module.exports.deletePolicy = deletePolicy;
module.exports.update = update;
module.exports.read = read;
module.exports.create = create;
module.exports.keyCount = keyCount;
module.exports.compare = compare;
module.exports.setPolicyId = setPolicyId;
module.exports.getPolicyId = getPolicyId;
module.exports.wp = wp;
module.exports.strip = strip;
