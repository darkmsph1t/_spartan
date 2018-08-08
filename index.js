#!/usr/bin/env node
'use strict';

var start = require("./start.js");
const text = require("cfonts");
var wp = require('./write-policy.js');
var bp = require('./write-bp.js');
var fs = require('fs');
var fse = require('fs-extra');
var pkg = fs.readFileSync("./package.json");
var pkgJson = JSON.parse(pkg);
var path = require('path');
var commander = require('commander');
var opt = "";
var secJsonPath = path.resolve("./security/security.json");
var secJsPath = path.resolve("./security/security.js");
var deleteLog = fs.createWriteStream('./logs/system/systemLogs');
var errorLog = fs.createWriteStream('./logs/errors/errorLog');
const { spawn } = require("child_process");

async function begin (opt){
  try {
    var a = await start.ans();
    if (typeof a == 'object'){
      var b = JSON.stringify(a, null, "  ");
      console.log(b);
      var c = await start.confirm();
      if (!c) {
        await begin(opt);
      } else {
        wp.writePolicy(a, opt);
        console.log("Security artifacts are located in: "+ secJsonPath);
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
  .version(pkgJson.version, '-v, --version')
  .option('init [y][yes]', 'Runs the configuration wizard, unless you also use the \'--y\' or \'--yes\' flag to just accept the policy defaults')
  .option('-d, --default', 'Builds a preconfigured, default security policy and security.js')
  .option('-f, --force', 'Force a complete regeneration of the boilerplate code defined in security.js. Typically used after making a manual adjustment to the security.json file')
  .option('-u, --update [--L]', 'Updates the latest policy as defined in security.json using the configuration wizard. Use \'--L\' to use long-form questions.')
  .option('-n, --no-overwrite', 'Creates a new policy and security.js file without overwriting the previous files. The filename will have the policy number appended')
  .option('--del, --delete [F]', 'Deletes the most recent security.json AND the security.js files. It does not remove any of the dependencies from package.json, unless it is run with the \'F\' flag')
  .option('--set-as-default', 'Sets the latest policy as the default. Any future policies generated with the default option will reference this policy.')
  .parse(process.argv);

  /*coming soon!
  .option('--audit [check]', 'Runs a basic code audit and fuzzer to see if the application is actually enforcing the policy')
  */

  if(commander.init){
    if(!commander.init[0]){
      console.log("Thanks for using _spartan! Here's how it works: \n* After answering a few questions, _spartan will generate a policy file (security.json).\n* Based upon the contents, _spartan generates the basic boilerplate code (security.js) which can be referenced in your application.\n* _spartan will also update the application's package.json file if additional dependencies are required.\n");
      opt = "init";
      begin(opt);
    } else {
      opt = "default";
      wp.writePolicy(undefined, opt);
      console.log("\n\nYour policy is located in: " + secJsonPath);
    }
    //may want to add something that also tells the user what modules were installed and which dependencies were added to package.json...wonder if we can keep this in a variable somewhere for easy reference later
  }
  else if (commander.default){
    opt = "default";
    wp.writePolicy(undefined, opt);
    console.log("\n\nYou selected "+ opt +". Excellent choice!\nYour policy is located in: "+ secJsonPath);
  }
  else if (commander.force){
      //parse security.json and re-write security.js
      opt = "force";
      bp.writeBp(opt);
  }
  else if (commander.update){
    opt = "update";
    if ("--L"){
      //populate the questionnaire defaults with the answers from existing security.json
      //run the long-form questionnaire using these defaults
    } else {
      //populate the questionnaire defaults with the answers from existing security.json
      //re-run the short questionnaire using these defaults
    }
  }
  else if (!commander.overwrite){
    opt = "no-overwrite";
    begin(opt);
    //// IDEA: Add option to run through the long-form questionnaire
  }
  else if (commander.delete){
    opt = "delete";
    async function del(){
      //ask the user if they are sure they want to do this: "Are you sure? This action is not reversable"
      var d = await start.deleteSecurity();
      if (d){
        if (commander.delete[0] == 'F'){
          //Identify all dependencies that were added. Remove dependencies from package.json using 'npm uninstall <package name> --save'. Remove security.json and security.js.
          var m = bp.addMiddleware();
          console.log("These are the packages that were installed by _spartan and will be removed: \n");
          for (var i = 0; i < m.length; i++){
            console.log(m[i]);
          }
          var f = await start.confirmPkgRemove();
          if (f){
              for (var j = 0; j < m.length; j++){
              //const child = spawn('npm', ['uninstall', m[j]]);
              console.log(m[j] + ' has been uninstalled');
              // child.stdout.on('data', (data) => {
              //   deleteLog.write(data);
              // });
              //
              // child.stderr.on('data', (data) => {
              //   errorLog.write(data);
              // });
            }
          } else {
            console.log("These packages were not removed");
          }
        } else {
          //remove security.json and security.js;
          fs.unlink(secJsonPath, function(err){
            if(err) {return console.log("File was not deleted " + err.code, err.path);}
            else { return console.log(secJsonPath + " was deleted successfully.");}
          });
          fs.unlink(secJsPath, function(err){
            if(err) {return console.log("File was not deleted " + err.code, err.path);}
            else { return console.log(secJsPath + " was deleted successfully.");}
          });
        }
      } else {
        console.log("Files were not deleted");
      }
    }
    del();
  }
  else if (commander.setAsDefault){
    opt = "setAsDefault";
    var secDefaultPath = './security/security-default.json';
    console.log("You selected: Set As Default\n");
    async function setAsDefault(){
        var s = await start.changeDefault();
        if (s){
            fs.copyFile(secJsonPath, secDefaultPath, function(err){
              if(err) { console.log("There was a problem with your request: " + err.code, err.path);}
            //return console.log("User selected to continue copy");
            var woot = JSON.parse(fs.readFileSync(secDefaultPath));
            woot._policyId = "";
            woot.applicationName = "";
            woot.applicationType = "";
            woot.hostname = "";
            woot.deployment = "";
            var toow = JSON.stringify(woot, null, ' ');
            fs.writeFile(secDefaultPath, toow, function (err){
              if(err) throw err;
              console.log("The file has been saved");
            });
          });
        } else {
          return console.log("User selected not to continue");
        }
      }
    setAsDefault();
} else if (commander.args.length == 0) {commander.help();}
  else {
    console.error(commander.args + " is not an available option. Please try again.");
  }
