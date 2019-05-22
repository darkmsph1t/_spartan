'use strict';
var chalk = require('chalk');
var uniqid = require('uniqid');
var t = require(`${__dirname}/transpose.js`);
// var fs = require('fs');
var fs = require('fs-extra')
var path = require('path');
const uniqueString = require('unique-string');
var pathToDefault = path.resolve(`${__dirname}/security-default.json`);

  /* POLICY METADATA INFO (IDs, STRUCTURE) */
  /**
   * @name keyCount
   * @description counts all of the keys in the policy. Used for comparison purposes
   * @param {Object} p policy object
   * @returns {Number} raw count of keys
   */
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
/**
 * @name compare
 * @description compares policy ids for equality. Used for policy updating
 * @param {String} pid1 policy id string
 * @param {String} pid2 policy id string
 * @returns {Boolean} returns true or false depending on value equality
 */
function  compare (pid1, pid2){
  if (pid1 === pid2){
    return true
  } else {
    return false
  }
}
/**
 * @name setPolicyId
 * @description sets the policy id for a given policy file
 * @param {Object} policy object containing policy parameters
 * @returns {Object} returns a policy object with a new unique policy id string
 */
function setPolicyId (policy){
  return policy["policyId"] = uniqueString();
}
/**
 * @name getPolicyId
 * @description fetches policy id from the active policy named security.json
 * @returns {String} returns policy id string
 */
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
/**
 * @name strip
 * @description strips policy meta data from an existing policy file. used to convert the existing policy to default
 * @param {Object} p policy object file
 * @returns {Object} returns the policy file with empty metadata
 */
function strip (p){
  p.policyId = '';
  p.applicationName = '';
  p.applicationType = '';
  p.internetFacing = '';
  return p
}
/**
 * @name wp
 * @description wp = 'write policy' responsible for actually writing the policy object to disc at the provided path
 * @param {Object} p policy object
 * @param {String} pathToPolicy string indicating where policy should be written
 * @returns {void}
 */
function wp (p, pathToPolicy){
  var wp = fs.createWriteStream(pathToPolicy);
  var convert = JSON.stringify(p, null, '  ');
  wp.write(convert);
  wp.close();
}
/* POLICY CRUD (CREATE, READ, UPDATE, DELETE)*/
/**
 * @name create
 * @description generates a new security policy (security.json) based upon answers to questions
 * @param {String} method defines what kind of policy to create
 * @param {Object} answers answers user provides from going through inquirer module will be empty for default method
 * @returns {Array} contains security.json, message, path to policy
 */
function create(method, answers = {}) {
  try {
    var policy = read(pathToDefault); // opens security-default.json
    var pathToPolicy;
    if (answers.appName === 'Get this from package.json file'){ // populates applicationName in security.json
      var pkgJson = read('./package.json')
      if (pkgJson instanceof Error) {
        policy.applicationName = 'No name found in package.json'
      } else {
        policy.applicationName = pkgJson.name
      }
    } else {
      policy.applicationName = answers.appName;
    }
    policy.policyId = uniqueString(); // creates a 36-digit policyId
    if (method === 'default'){
      pathToPolicy = './security.json';
      policy.applicationType = 'Web';
      policy.internetFacing = true;
      wp(policy, pathToPolicy); // what to write & where to write it/name it
    } else if (method === 'no-overwrite'){
      pathToPolicy = 'security-' + (policy.policyId).match(/.{1,8}/g)[3] + '.json'; // sets filename to security-[last 4 of the policy id]
      var o = t.transformer(answers, policy) // interprets the answers provided into the required policy
      wp(o, pathToPolicy); // what to write, where/how to write it
    } else {
      pathToPolicy = './security.json';
      console.log ('Writing policy for ' + policy.applicationName + '\n');
      var p = t.transformer(answers, policy); // mutates the answers into a new policy based upon the structure from security default
      wp(p, pathToPolicy); // what to write, where/how to write it
    }
    /* a whole bunch of stuff to translate the answers into the final policy */
    var msg = chalk.magenta(`Congrats! The policy was successfully created at: ${path.resolve(pathToPolicy)}\n`);
    return [policy, msg, path.resolve(pathToPolicy)];
  } catch (e) {
    console.log('Something went wrong creating the policy ' + e);
  }
}
/**
 * @name read
 * @description reads the file at the location provided by pathToRead
 * @param {String} pathToRead filename of the policy file
 * @returns {Object} returns the JSON file at the location provided in pathToRead 
 */
function read(pathToRead) {
  try {
    var pathToPolicy = path.resolve(pathToRead);
    var m = JSON.parse(fs.readFileSync(pathToPolicy));
    return m;
  } catch (e) {
    let err =  new Error(`Could not find file ${pathToRead}`)
    return err
  }
}
/**
 * @name update
 * @description interprets new answers in existing policy file
 * @param {Object} newAnswers object containing answers from user
 * @returns {Array} policy object and message string
 */
function update(newAnswers) {
  try{
    var oldPolicy = read('./security.json'); // opens existing policy file
    var newPolicy = t.transformer(newAnswers, oldPolicy); // transforms new answers into old policy
    if (compare(oldPolicy.policyId, newPolicy.policyId) === false) { // if the policyIds don't match throw an error
      throw new Error ('The policy did not update correctly. Please try again');
    } else {
      wp(newPolicy, './security.json'); // otherwise write the new policy at the old location
      var message = 'The policy ' + newPolicy.policyId + ' was updated.';
      return [newPolicy, message];
    }
  } catch (e){
    console.log('There was a problem updating policy ' + oldPolicy.policyId + '\n' + e.code, e.path);
  }
}
/**
 * @name deletePolicy
 * @description destroys the policy located in the default location
 * @returns {String} returns a confirmation message string
 */
function deletePolicy() {
  try {
    var pathToPolicy = path.resolve('./security.json'); // get the path to the policy file
    var pathToBoilerPlate = path.resolve('./security.js'); // get the path to the boilerplate code pointer file
    var pathToCodeFolder = path.resolve('./security/') // get the path to the code folder
    var m = JSON.parse(fs.readFileSync(pathToPolicy)); // read the file
    var policyNumber = m.policyId; // get the policyId
    fs.unlink(pathToBoilerPlate, function (err){ // remove the boilerplate pointer file
      if (err) { throw new Error (`Couldn't remove ${pathToBoilerPlate}: ${err}`) } 
    });
    fs.unlink(pathToPolicy, function (err){ // remove the policy file
      if (err) {  throw new Error (`Couldn't remove ${pathToPolicy} : ${err}`);} 
    });
    fs.remove(pathToCodeFolder, function (err) { // remove all of the code in the code folder
      if (err) { throw new Error(`Couldn't remove folder ${pathToCodeFolder}: ${err}`)}
    });
    var msg = chalk.magenta(`All artifacts related to policy ${policyNumber} have been removed from the file system.\n`);
    console.log(msg);
    return msg;
  } catch (e){
    console.log(policyNumber + 'deleted\n' + e);
  }
}
module.exports = {
  deletePolicy : deletePolicy,
  update : update,
  read : read,
  create : create,
  keyCount : keyCount,
  compare : compare,
  setPolicyId : setPolicyId,
  getPolicyId : getPolicyId,
  wp : wp,
  strip : strip
}
// module.exports.deletePolicy = deletePolicy;
// module.exports.update = update;
// module.exports.read = read;
// module.exports.create = create;
// module.exports.keyCount = keyCount;
// module.exports.compare = compare;
// module.exports.setPolicyId = setPolicyId;
// module.exports.getPolicyId = getPolicyId;
// module.exports.wp = wp;
// module.exports.strip = strip;
