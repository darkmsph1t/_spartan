#!/usr/bin/env node

'use strict';
var start = require("./start.js");
//var spartan = require("./spartan.js");
const text = require("cfonts");
var wp = require('./write-policy.js');
var path = require('path');
var commander = require('commander');

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
text.say('_spartan', {
  font : 'simple',
  align : 'left',
  colors : ['red'],
  space : false
});
text.say('by @darkmsph1t', {
  font : 'console',
  align : 'center',
  colors : ['cyan'],
  space : false
});

//spartan.banner("_spartan");
commander
  .version('0.0.1')
  .option('init, [--y][--yes]', 'Runs the configuration wizard, unless you also use the -y | --yes flag to just accept the policy defaults')
  .option('-d, --default', 'Builds a preconfigured, default security policy and security.js')
  .option('-f, --force', 'Force a complete regeneration of the boilerplate code defined in security.js. Typically used after making a manual adjustment to the security.json file')
  .option('-u, --update [--L]', 'Updates the latest policy as defined in security.json using the configuration wizard. Use \'-L\' to use long-form questions.')
  .option('-n, --no-overwrite', 'Creates a new policy and security.js file without overwriting the previous files. The filename will have the policy number appended')
  .option('[--delete]', 'Deletes the most recent security.json AND the security.js files. It does not remove any of the dependencies from package.json, unless it is run with the -force flag')
  .option('[--set-as-default]', 'Sets the latest policy as the default. Any future policies generated with the default option will reference this policy.')
  .parse(process.argv);

  if(commander.init){
    console.log("Thanks for using _spartan! Here's how it works: \n * After answering a few questions, _spartan will generate a policy file (security.json).\n * Based upon the contents, _spartan generates the basic boilerplate code (security.js) which can be referenced in your application.\n * _spartan will also update the application's package.json file if additional dependencies are required.\n");
    begin();
  }
  else if (commander.args.length == 0) {commander.help();}
  else {
    //something
  }
