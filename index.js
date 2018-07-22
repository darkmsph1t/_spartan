'use strict';
var ask = require("./questions.js");
var fs = require("fs");
var inquirer = require("inquirer");

/*
1. Ask the user the questions and store in a temporary variable, tmp. Should this be a function?
2. Ask the user if this is ok
  - if it is ok, then begin the process of transposing the answers
  - if it is not ok, then ask the users the questions again
3.
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
  if (foo.confirmValues){
    console.log("writing policy...")
    console.log(a.exposure);
  }else {
    confirm();
  }
}

confirm();
