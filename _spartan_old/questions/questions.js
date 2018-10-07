'use strict';
var inquirer = require('inquirer');

async function question(q){
  try {
    var foo = await inquirer.prompt(q);
    return foo;
  } catch (e) {
    console.log("failure to launch");
  }
}
module.exports.question = question;
