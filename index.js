'use strict';
var ask = require("./questions.js");
var fs = require("fs");
var inquirer = require("inquirer");
var wp = require('./write-policy.js');

/*
1. Ask the user the questions and store in a temporary variable, tmp. Should this be a function?
2. Ask the user if this is ok
  - if it is ok, then begin the process of transposing the answers
  - if it is not ok, then ask the users the questions again
*/
var confirmPolicy = [{
    type : 'confirm',
    name : 'confirmValues',
    message : 'Is this ok?',
    default : true
  }];

async function ans () {
  var a = await ask.question();
  return a;
}

async function confirm () {
  var a = await ans();
  console.log(JSON.stringify(a, null, '  '));
  var foo = await inquirer.prompt(confirmPolicy);
  try {
    if (foo.confirmValues){
      console.log("writing policy...\n");
      wp.writePolicy(a);
    } else {
      confirm();
    }
  } catch (err) {
    console.log("Sad Face! :-( something went wrong writing your policy\n");
    console.log (err);
  }

}

confirm();
