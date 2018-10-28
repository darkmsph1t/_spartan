'use strict';
var expect = require('chai').expect;
var i = require('../index.js');
var commander = require('commander');
var p = require('../policy.js');
var path = require('path');
var fs = require('fs');
const defaultPath = '../security-default.json';
const pathToPolicy = '../security.json';
const boilerplatePath = path.resolve('../security.js');
const { spawn } = require('child_process');

describe('APPLICATION KICKOFF', function (){
    before(function (){
      var pkg = p.read('./package.json');
      commander
        .version(pkg.version, '-v, --version')
        .option('init [y][Y][L]',   'Initialize a new policy. Use y | Y for defaults. Use L for long-form questions\n')
        .option('-d, --default' ,   'Builds a preconfigured, default security policy and security.js installed modules\n')
        .option('-u, --update [L]', 'Update the existing policy. Use the L flag to update using long-form questions\n')
        .option('-f, --force '   ,  'Force a complete regeneration of the boilerplate code defined in security.js. \n' +
                                    '\t\t\tTypically used after making a manual adjustment to the security.json file.\n')
        .option('--no-overwrite',   'Creates a new policy without overwriting the existing policy\n')
        .option('--delete [F]'  ,   'Remove the policy and boilerplate code. Use F option to remove any installed modules\n')
        .option('--set-as-default', 'Sets the current policy as the default policy\n')
        .parse(process.argv);
    });
    describe('COMMAND LINE', function (){
      it('should tell me if I try to use an option that is not available', function(){
        var input = 'sdkfndksfjkls';
        const foo = spawn('node', ['../index.js', input]);
        var a = function(){
          if(commander.args !== 'init' || commander.args !== '-d'|| commander.args !== '-u' ||
             commander.args !== '-f' || commander.args !== '--no-overwrite' || commander.args !== '--delete' ||
             commander.args !== 'set-as-default'){
               throw new Error ("That is not an available option");
             } else {
               console.log(commander.args);
             }
        }
        expect(a).to.throw();
        expect(typeof input).to.be.a('string');
      });
      it('should only accept dashes and strings as input', function (){
        const notAString = 192840284;
        const stringTest = spawn('node', ['../index.js', notAString]);
        var stringTestFunction = function () {
          if(commander.args !== 'init' || commander.args !== '-d'|| commander.args !== '-u' ||
             commander.args !== '-f' || commander.args !== '--no-overwrite' || commander.args !== '--delete' ||
             commander.args !== 'set-as-default'){
               throw new Error ("That is not an available option. Try again with -h for available options");
             } else {
               console.log(commander.args);
             }
        }
        expect(stringTestFunction).to.throw();
      });
      describe('Init Option', function (){
        it('should throw an error if an invalid option is added to the end of the command', function(){
          var input = 'sdkfndksfjkls';
          const bar = spawn('node', ['../index.js', 'init', input]);
          var b = function (){
            if (commander.init[0] !== 'y' || commander.init[0] !== 'L') {
                throw new Error ("This is not a valid option");
              }
            }
            expect(b).to.throw();
        });
      });
      describe('Update Option', function (){
        it('should run the long-form questions if the -L flag is included', function (){
          var input = 'L';
          const moo = spawn('node', ['../index.js', '-u', input]);
          var c = function (){
            if(commander.update[0] !== 'L'){
              throw new Error ("Only long-form option is available with this command");
            } else {
              console.log("run long-form questions");
            }
          }
          expect(c).to.throw();
        });
      });
      describe('Delete Option', function (){
        it('should throw an error if any character other than \'F\' is added to the end of the command', function (){
          var bull = 999;
          const cow = spawn('node', ['../index.js', '--delete', bull]);
          var calf = function (){
            if(commander.update[0] !== 'F'){
              throw new Error ("Only force option is available with this command");
            } else {
              console.log("Force option invoked");
            }
          }
          expect(calf).to.throw();
        });
        it('should respect both --del and --delete options', function (){
          const goat = spawn('node', ['../index.js', '--del']);
          const sheep = spawn('node', ['../index.js', '--delete']);
          expect(goat).to.be.ok;
          expect(sheep).to.be.ok;
        });
      });
      describe('Set-As-Default Option', function (){
        //no additional expectations that haven't already been covered
      });
      describe('No-Overwrite Option', function (){
        //no additional expectations that haven't already been covered
      });
      describe('Force Option', function (){
        //no additional expectations that haven't already been covered
      });
      describe('Default Option', function (){
        //no additional expectations that haven't already been covered
      });
    });

    describe ('Ask Tests', function (){
      it('should accept an array as an input', function (){
        setTimeout(function (){
          var w = require('../question.js').nq;
          var d = function (){
            if(typeof w !== 'array'){
              throw new TypeError ('The expected input was an array. Received ' + typeof w + ' instead.');
            }
          }
          expect(d).to.throw();
        }, 1000);
      });
      it('should fully execute all of the questions in the array prior to returning a value', function (){
        setTimeout(function (){var x = require('../question.js').confirmDelete;
        var g = function() {
          if(typeof i.ask(x) !== 'Promise'){
            throw new Error ('Sync error');
          }
        }
        expect(g).to.throw();}, 1000);
      });
      it('should return an object as an output', function (){
        setTimeout(function(){
          var y = require('../question.js').nq;
          var askTest = function (){
            if (typeof i.ask(y) !== 'object'){
              throw new TypeError ('TypeError: Object expected');
            }
          }
        expect(typeof i.ask(y)).to.deep.equal('object');
        expect(askTest).to.not.throw();
        }, 1000);
      });
      // it ('should throw an error if it can\'t return the answers object', function (){
      //   var j = function(){
      //     if(1 == 1){
      //       throw new Error ('The answers to the questions could not be returned');
      //     }
      //   }
      //   expect(j).to.throw();
      // });
    });
    describe('Begin Tests', function(){
      describe('Init', function (){
        it('should run the short questions if no additional flags are run', function (){
          setTimeout(function (){expect(i.begin("init")).to.be.ok;}, 1000);
        });
        it('should launch the questions again if the user does not confirm answers are ok', function(){
          setTimeout(function (){
            var wut = require('../question.js').confirmSettings;
            var confirm = i.ask(wut);
            var yup = function(){
              if(confirm.settingsConfirm == false){
                begin('init');
              }
            }
            expect(yup).to.be.ok;
          });
        }, 2000);

      });
      describe('Default', function (){
        it('should bypass the questions if the default option is selected', function (){
          setTimeout(function(){expect(i.begin('default')).to.be.ok;}, 1900);
        });
      });
      describe('Update', function (){
        it('should launch the questions again if the user does not confirm answers are ok', function(){
          var say = require('../question.js').confirmSettings;
          var bloop = i.ask(say);
          var hey = function(){
            if(bloop.settingsConfirm == false){
              begin('update');
            }
          }
          expect(hey).to.be.ok;
        });
        it('should fetch the existing policy and pass to the update function', function (){
          setTimeout(function(){expect(i.begin("update")).to.be.ok;}, 1800);
        });
      });
      describe('Delete', function(){
        it('should prompt me for confirmation of my decision to delete', function (){
          setTimeout(function (){expect(i.begin('delete')).to.be.ok;
          expect(i.begin('delete', 'F')).to.be.ok;}, 2500);
        });
      });
      describe('Set-As-Default', function (){
        it('should call a function to strip policy metadata from the policy file', function (){
          setTimeout(function (){
            try {
              var r = p.read('./security.json');
              i.begin('set-as-default');
              var s = p.read('./security-default.json');
            } catch (e) {
              console.log("Couldn't find security.json");
            }
            expect(r.policyId).to.not.equal(s.policyId);
            expect(r.applicationName).to.not.equal(s.applicationName);
            expect(r.applicationType).to.not.equal(s.applicationType);
          }, 3300);
        });
        it('should overwrite the existing security-default.json file using the contents of security.json', function (){
          setTimeout(function (){expect(i.begin('set-as-default')).to.be.ok;}, 3456);
        });
        it('should tell me if the overwrite was successful', function (){
          setTimeout(function (){
            var sadMessage = i.begin('set-as-default');
            expect(sadMessage).to.include('Successfully replaced');}, 4000)
          });
        });
        describe('Force', function (){
          it('should throw an error if security.json doesn\'t already exist', function (){
              setTimeout(function (){
                var whereTheJson = function (){
                    if (p.read('./security.json')){
                      console.log('yay!')
                    } else {
                        throw new Error ('No policy file found');
                    }
                  }
                  expect(whereTheJson).to.not.throw();
              }, 2345);
          });
          it('should call the writeBoilerplate function when invoked', function (){
            setTimeout(function (){expect(i.begin('force')).to.be.ok;}, 2800);
          });
          it('should throw an error if the security.json file is in the wrong format', function (){
            setTimeout(function(){var formatCheck = function (){
              if(Object.keys(p.read(pathToPolicy)).length !== Object.keys(p.read(defaultPath)).length){
                throw new Error ('The policy file is in the wrong format');
              }
            }
            expect(formatCheck).to.throw();}, 4000);
          });
          it('should return a new javascript file', function (){
            setTimeout(function (){
              var findBoilerplate = function (){
                if (fs.readFileSync(boilerplatePath)) {console.log('yay!');}
                else { throw new Error}
              }
              expect(findBoilerplate).to.throw();
            }, 5000);
          });
          //it('should call an intepreter function on the security.json file');
          it('should tell me if the force was successful', function (){
            setTimeout(function (){
              var fTest = i.begin('force').message;
              expect(fTest).to.include('Successfully wrote boilerplate');
            }, 3456);
          });
        });
        describe('No Overwrite', function (){
          it('should NOT overwrite an existing security.json file or attempt to find an existing security.json file', function () {
            setTimeout(function(){expect(i.begin('no-overwrite')).to.be.ok;}, 3500);
          });
        });
      });
    });
