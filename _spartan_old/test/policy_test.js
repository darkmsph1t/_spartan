'use strict';

var expect = require('chai').expect;
var fs = require('fs');
var path = require('path');
var p = require('../policy.js');
var idx = require('../index.js');
var pathToDefault = path.resolve('security-default.json');
var pathToAnswers = path.resolve('./answers.json');
var pathToPolicy = path.resolve('./security.json');
var answers = p.read(pathToAnswers);

describe ('POLICY GENERATION TESTS', function (){
  describe ('Policy Creation', function (){
    it('should assign a unique policy number', function (){
      var p1 = p.setPolicyId(answers);
      var p2 = p.setPolicyId(answers);
      const match = p.compare(p1,p2);
      expect(match).to.be.false;
    });
    it('the final policy should be an object', function(){
      var test = p.create('default');
      expect(test[0]).to.be.an('object');
    });
    it('should tell me where the final policy is stored', function (){
      var msg = p.create('default')[1];
      expect(msg).to.include('policy was successfully created');
    });
    it ('should throw an error if policy creation fails', function(){
     var noCreate = function () {
        if (p.create('default')[0]){
          console.log('yay!')
        } else {
            throw new Error ('Unable to create policy');
        }
      }
      expect(noCreate).to.not.throw();
    });
    it ('should retain the original structure of the default policy, even if some components are deactivated', function (){
      var t = p.create('default')[0];
      var u = p.read(pathToDefault);
      var allKeys = function(policy){
        var k = [];
        for (var key in policy){
          if (typeof policy[key] == 'object'){
            k.push(policy[key]);
            allKeys(Object.keys(policy[key]));
          } else {
            k.push(key);
          }
        }
        return k;
      }
      expect(allKeys(t)).to.deep.equal(allKeys(u));
    });
    describe ('Transpose Values', function (){
      it('should accept an object as an input');
      it('should return an object');
      it('should call subfunctions depending on values in the answers object');
      it('should throw an error if any of the subfunctions fail');
    });
  });
  describe ('Policy Read', function (){
    it('should throw an error if the policy doesn\'t exist', function (){
      setTimeout(function(){
        p.create('default');
      var huh = p.read('./security.json');
        var noPolicy = function (){
          if (huh){
            console.log('yay!')
          } else {
              throw new Error ('No policy file found');
          }
        }
        expect(noPolicy).to.not.throw();}, 2500);
    });
  });
  describe ('Policy Updating', function (){
    it('should retain the existing policy number', function (){
      setTimeout(function(){
        p.create('default');}, 2000);
        var o = p.read('./security.json');
        var n = p.update(answers);
        expect(n[0].policyId).to.equal(o.policyId);
    });
    // I'm not really sure what I meant by this
    it ('should throw an error if the new property values arent the right type');
    it('should throw an error if the update is unsuccessful', function (){
      var msg = p.update(answers)[1];
      var noUpdate = function (){
        if(!msg){ throw new Error ('There was a problem updating the policy')}
      }
      expect(msg).to.include('was updated');
      expect(noUpdate).to.not.throw();
    });
  });

  describe ('Policy Destruction', function (){
    describe('Delete Tests', function (){
      it('should throw an error if an existing policy could not be found', function (){
        var test = function (){
          if(!p.read('./security.json')){
            throw new Error ("File Not Found");
          }
        }
        expect(test).to.not.throw();;
      });
      it('should throw an error if an existing security.js could not be found', function (){
        //index.begin('force');
        setTimeout(function(){var bp = require('../security.js');
        var noBoilerplate = function (){
        if(!bp){
            throw new Error ("File Not Found");
          }
        }
        expect(noBoilerplate).to.not.throw();}, 3000);
      });
      it('should completely remove the correct policy from the file system', function (){
      var d = p.create('default');
      var noDelete = function (d) {
        if (!p.deletePolicy()){
          throw new Error ("There was a problem deleting policy " + d.policyId);
        } else {
          console.log("Policy " + d.policyId + " was successfully deleted");
        }
      }
      expect(noDelete).to.throw();
      });
      // it ('should record \'delete\' actions for the policy number in an audit log', function (){
      //   p.deletePolicy();
      //   var key = Object.keys(audits);
      //   var lastKey = key[key.length-1];
      //   setTimeout(function (){
      //     expect(lastKey['deleted']).to.not.equal(undefined);}, 1000);
      // });
      // it('the policy number SHOULD NOT be used on any other policy once the policy is destroyed', function (){
      //   var penny = p.create('default')[0].policyId;
      //   var keys = Object.keys(audits);
      //   for (var k in audits){
      //       if (audits[k].deleted !== undefined){
      //         expect(penny).to.not.equal(k);
      //       }
      //   }
      // });
      it ('should tell me when the policy is removed', function (){
        var colt = p.deletePolicy();
        console.log(colt);
        expect(colt).to.include('have been removed from the file system');
      });
    });
  });
  describe('No-Overwrite Tests', function(){
    it('should NOT overwrite an existing security.json policy', function (){
      //expect().is.not.equal.to();
    });
    it('should tell me the name of the file that is created');
    it('should tell me where the file has been written');
  });
  describe ('Default Policy', function (){
    it ('should throw an error if the default policy does not exist', function (){
        var base = p.read(pathToDefault);
        var ball = function (){
          if(!base) { throw new Error ("Default Policy Not Found");}
        }
      expect(ball).to.be.ok;
      expect(ball).to.not.throw();
    });
    describe('Default Policy Restoration', function (){
      it('should allow me to restore my default policy to factory settings');
    });
  });
});
