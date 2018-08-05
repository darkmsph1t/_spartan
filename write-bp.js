'use strict';

var fs = require("fs");
var path = require('path');

function writeBp(opt){
  try {
    var secJson = JSON.parse(fs.readFileSync("./security/security.json"));
    var secJs = fs.createWriteStream("./security/security.js");
    secJs.write('\'use strict\';\n');
    secJs.close();
    var absolutePath = path.resolve("./security/security.js");
    console.log("The "+ opt + " option was selected.\n The new security.js is stored in " + absolutePath);

  } catch (e) {
    console.log("Unable to find security.json file. Please run _spartan again to build your custom policy.")
    console.error(e.code, e.path);
  }
}
module.exports.writeBp = writeBp;
