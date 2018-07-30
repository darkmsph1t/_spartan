'use strict';
var start = require("./start.js");
var spartan = require("./spartan.js");
var wp = require('./write-policy.js');
var path = require('path');

async function begin (){
  try {
    var a = await start.ans();
    if (typeof a == 'object'){
      var b = JSON.stringify(a, null, "  ");
      console.log(b);
      var c = await start.confirm();
      if (!c) {
        await begin();
      } else {
        wp.writePolicy(a);
        console.log("Security artifacts are located in the current working directory");
      }
    } else {
      console.log ("there was a problem with this request, yo!");
    }
  } catch (e) {
    console.log ("no work\n" + e);
  }

}

console.log("Thanks for using _spartan! Here's how it works: \n * After answering a few questions, _spartan will generate a policy file (security.json).\n * Based upon the contents, _spartan generates the basic boilerplate code (security.js) which can be referenced in your application.\n * _spartan will also update the application's package.json file if additional dependencies are required.\n\n");

//spartan.banner("_spartan");
begin();
