'use strict';
var figlet = require("figlet");

function banner (input) {
  figlet(input, function(err, data){
    if (!err){
      return console.log(data + "\n Thanks for using _spartan! Here's how it works: \n * After answering a few questions, _spartan will generate a policy file (security.json).\n * Based upon the contents, _spartan generates the basic boilerplate code (security.js) which can be referenced in your application.\n * _spartan will also update the application's package.json file if additional dependencies are required.");
    }
    else {
      return "_SPARTAN";
    }
  });
}
banner("_spartan!");
module.exports.banner = banner;
