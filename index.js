#! /usr/bin/env node
'use strict'
var commander = require('commander')
const text = require('cfonts')
var { spawn, spawnSync } = require('child_process')
var chalk = require('chalk')
var hash
var p = require('./policy')
var a = p.read(__dirname +'/answers.json')
var pkg = p.read(__dirname +'/package.json')
var short = require(__dirname + '/question').nq
var long = require(__dirname + '/question').lnq
var confirmDelete = require(__dirname + '/question').confirmDelete
var confirmSettings = require(__dirname + '/question').confirmSettings
var confirmDeleteForce = require(__dirname + '/question').confirmDeleteForce
var restoreDefault = require(__dirname + '/question').restoreDefault
var inquirer = require('inquirer')
var bp = require(__dirname + '/boilerplate')
var all = ['snyk', 'bcrypt', 'passport', 'rbac', 'cors', 'winston', 'mime-types', 'js-cookie', 'cookie-parser', 'helmet', 'mongodb', 'csurf', 'validator', 'joi', 'redis', 'forms']

async function ask (q) {
  var answers = await inquirer.prompt(q)
  return answers
}
function integrity (p) {
  try {
    const sha = spawn('shasum', ['-b', '-a', '384', p])
    const xxd = spawn('xxd', ['-r', '-p'])
    const b = spawn('base64')
    sha.stdout.pipe(xxd.stdin)
    xxd.stdout.pipe(b.stdin)
    b.stdout.on('data', (data) => {
      console.log((`SHA-384 hash of ${chalk.yellow(p)}: ${chalk.magenta(data)}`))
      hash = data
      return hash
    })
    b.stderr.on('data', (data) => {
      console.error(`Error hashing security.json: ${data}`)
    })
  } catch (e) {
    throw new Error(`Could not calculate hash of security.json, ${e}`)
  }
}
function nextSteps (modules) {
  var npmCommand = chalk.bold.yellow(`npm install ${modules}`)
  var url = chalk.green(`https://github.com/darkmsph1t/_spartan/wiki`)
  var conf = chalk.bold.cyan(`javascriptEnabled: false`)
  var whatsNext = `Next steps: \n\t1. Install necessary packages (copy/paste at command prompt inside project directory): \n\t\t\`${npmCommand}\n\t\t${chalk.cyan.dim('Psst! If you haven\'t already, install eslint-plugin-security to prevent vulnerabilties from being written into your code')}\`\n\t2.Disable Javascript execution in Mongo. \n\t\tAdd the following line inside the ${chalk.red('security section')} to \`${chalk.red.underline('mongod.conf')}\`: ${conf}\n\t\t${chalk.red.dim('Psst! Be sure to save the file and restart mongod!')}\n\t3.Wire in \`security.js\` components to your app. \n\t\tCheck ${url} for additional information\n`
  return whatsNext
}

async function begin (cmd, opt = []) {
  // default
  if ((cmd === 'init' && opt === 'y') || (cmd === 'init' && opt === 'Y') || cmd === 'default') {
    var basic = p.create('default')
    console.log(basic[1])
    integrity(basic[2])
    var boiler = await bp.writeBoilerplate(basic[0])
    // console.log(`The following modules were installed: \n`);
    // for (var bin = 0; bin < (basicBp.modules).length; bin ++){
    //   console.log(`${chalk.yellow(basicBp.modules[bin])}`);
    // }
    console.log(boiler.message + '\n')
    integrity(boiler.pathToFile)
    await console.log(nextSteps(boiler.modules))
  } else if (cmd === 'update') { // update
    if (opt === 'L') {
      var l = await ask(long)
      console.log(l)
      var cl = await ask(confirmSettings)
      if (cl.settingsConfirm) { p.create(cmd, l) } else { begin(cmd, 'L') }
    } else {
      var k = await ask(short)
      //  p.create(cmd, k);
      console.log(k)
      var ck = await ask(confirmSettings)
      if (ck.settingsConfirm) {
        var up = await p.create(cmd, k)
        console.log(up[1])
        integrity(up[2])
        var upBp = await bp.writeBoilerplate(up[0])
        integrity(upBp.pathToFile)
      } else { begin(cmd) }
    }
  } else if (cmd === 'force') { // force
    try {
      var finishedPolicy = p.read('./security.json')
      var f = await bp.writeBoilerplate(finishedPolicy)
      console.log('The following modules should be installed as a result of the force command:')
      console.log(chalk.yellow(bp.matches(all, f.modules)))
      // removeModules(oldModules);
      console.log('The following modules should be removed as a result of the force command: ')
      console.log(chalk.red(bp.diff(all, f.modules)))
      integrity('security.js')
    } catch (e) {
      console.log('No policy file found. Please run `_spartan init` to build your policy first.')
    }
  } else if (cmd === 'delete') { // delete
    if (opt === 'F') {
      var forceConfirm = await ask(confirmDeleteForce)
      if (forceConfirm.deleteForceConfirm) {
        p.deletePolicy()
        bp.removeModules()
      } else { console.log('Policy Not deleted\n') }
    } else {
      var d = await ask(confirmDelete)
      if (d.deleteConfirm) { p.deletePolicy() } else { console.log('Policy Not deleted\n') }
    }
  } else if (cmd === 'no-overwrite') { // no-overwrite
    try {
      var nope = await ask(short)
      console.log(nope)
      var bop = await ask(confirmSettings)
      if (bop.settingsConfirm) {
        p.create(cmd, a)
      } else {
        begin(cmd)
      }
    } catch (e) {
      throw new Error('Could not create a separate policy file')
    }
  } else if (cmd === 'set-as-default') { // set-as-default
    try {
      var newPolicy = p.strip(p.read('./security.json'))
      p.wp(newPolicy, `${__dirname}/security-default.json`)
      var successMessage = 'Successfully replaced default policy'
      integrity(`${__dirname}/security-default.json`)
      console.log(successMessage)
      return successMessage
    } catch (e) {
      console.error('No policy file found. Please run `_spartan init` to build your policy first.')
    }
  } else if (cmd === 'integrity') {
    integrity('./security.json')
    integrity('./security.js')
  } else if (cmd === 'resetDefault') {
    var r = await ask(restoreDefault)
    if (r.restore) {
      const downloadUrl = 'https://raw.githubusercontent.com/darkmsph1t/_spartan-factory-default/master/security-default.json'
      const checkHashUrl = 'https://github.com/darkmsph1t/_spartan-factory-default'
      console.log(`Restoring security-default.json from ${chalk.yellow(downloadUrl)}...`)
      try {
        var reset = spawnSync('wget', [downloadUrl, '-O', `${__dirname}/security-default.json`], { stdio: 'pipe' })
        console.log(reset.output[2].toString())
        integrity(__dirname + '/security-default.json')
        console.log(`Default file has been restored. Check ${chalk.yellow(checkHashUrl)} to validate integrity of the file before proceeding`)
      } catch (err) {
        console.log(`There was a problem restoring the default policy to factory settings, ${err}. Download the policy directly from ${downloadUrl}`)
      }
    }
  } else {
    var i = await ask(short)
    console.log(i)
    var z = await ask(confirmSettings)
    if (!z.settingsConfirm) {
      begin('init')
    } else {
      var full = p.create('init', i)
      console.log(full[1])
      integrity(full[2])
      var fullBp = await bp.writeBoilerplate(full[0])
      // console.log(`The following modules were installed: \n`);
      // for (var fin = 0; fin < (fullBp.modules).length; fin ++){
      //   console.log(`${chalk.yellow(fullBp.modules[fin])}`);
      // }
      console.log(fullBp.message + '\n')
      integrity(fullBp.pathToFile)
      console.log(nextSteps(fullBp.modules))
    }
  }
}
text.say('_spartan', {
  font: 'simple',
  align: 'left',
  colors: ['red'],
  space: false
})
text.say('by @darkmsph1t', {
  font: 'console',
  align: 'center',
  colors: ['cyan'],
  space: false
})

commander
  .version(pkg.version, '-v, --version')
  .option('init, [y][Y][L]', 'Initialize a new policy. Use y | Y for defaults. Use L for long-form questions\n')
  .option('-D, --default', 'Builds a preconfigured, default security policy and security.js installed modules\n')
  .option('-u, --update [L]', 'Update the existing policy. Use the L flag to update using long-form questions\n')
  .option('-f, --force ', 'Force a complete regeneration of the boilerplate code defined in security.js. \n' +
                                 '\t\t\t Typically used after making a manual adjustment to the security.json file.\n')
  .option('--no-overwrite [L]', 'Creates a new policy without overwriting the existing policy. \n' +
                                  '\t\t\t Use L for long-form questions\n')
  .option('--del, --delete [F]', 'Remove the policy and boilerplate code. Use F option to remove any installed modules\n')
  .option('--set-as-default', 'Sets the current policy as the default policy\n')
  .option('-R, --reset-default', 'Restores the default policy to factory settings. Requires wget\n')
  .option('-i, --integrity', 'SHA-384 hash of existing policy')
  .option('--deploy', 'Deploys the app using the specification from security.json')
  .parse(process.argv)

if (commander.version && pkg === undefined) {
  pkg.version = '0.0.1'
  console.log('Couldn\'t find package.json file. Have you already run `npm init`?')
}   
if (commander.init) {
  if (commander.init === 'y' || commander.init === 'Y' || commander.init === 'L') {
    begin('init', commander.init)
  } else {
    begin('init')
  }
} else if (commander.default) {
  begin('default')
} else if (commander.update) {
  if (!p.read('./security.json')) {
    throw new Error('No policy file found')
  } else {
    begin('update')
  }
} else if (commander.force) {
  begin('force')
} else if (!commander.overwrite) {
  begin('no-overwrite')
} else if (commander.delete) {
  begin('delete')
  if (commander.delete[0] === 'F') {
    begin('delete', 'F')
  }
} else if (commander.setAsDefault) {
  begin('set-as-default')
} else if (commander.integrity) {
  begin('integrity')
} else if (commander.resetDefault) {
  begin('resetDefault')
} else if (commander.args.length === 0) { commander.help() } else {
  console.log('That is not an avaiable option')
}
module.exports.ask = ask
module.exports.begin = begin
module.exports.integrity = integrity
