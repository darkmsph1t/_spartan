[![Coverage Status](https://coveralls.io/repos/github/darkmsph1t/_spartan/badge.svg?branch=master)](https://coveralls.io/github/darkmsph1t/_spartan?branch=master)
## THIS. IS.\_SPARTAN!
node application to package &amp; configure common security middleware into your application => returns a policy file and boilerplate code

## QUICK START!
1. Create a new application: npm init to accept the defaults be sure to use the ‘-y’ flag
optional: Enable version control w/ git: `git init`
1. Install the package: <h2>`npm install -g spartan-shield`</h2><br> _installs \_spartan as a command line module you can use in any project_
   * There’s some wonkiness installing on Linux using the -g flag as access to /usr/bin/ requires elevated permissions. To overcome this, install as `sudo npm install -g spartan-shield`. If necessary, you should still be able to install and run it locally without the global flag
1. Run the package: `_spartan init` creates a policy based upon your answers to a few questions. Use ‘y’ to generate a default policy and boilerplate code

### HOW YOU KNOW IT WORKED
Assuming there are no errors, you will see 3 new files/folders in your local directory:

* security.json => the policy file based upon the questions you answered OR the default policy
* security.js => the module which points to all of the submodules generated based upon your policy
* security/ => all of the pre-configured submodules generated from your policy. security.js points to these files.

### HOW YOU KNOW IT DIDN’T WORK
_spartan throws ‘ENOENT’ (no entity) errors for each of the following conditions

  * No package.json file => either run npm init or make sure to run _spartan from the same location as package.json
  * No default policy => if you run `_spartan -D` and get this error, then \_spartan can’t find the default policy (packaged with the module); the quickest way to deal with this is to pull the default policy from github by running `_spartan -R` which restores the factory default policy
    * Default policy restoration requires wget. If you don’t already have this installed, use homebrew or similar to get this package

_**Other potential installation errors**_

Required programs missing => \_spartan won’t be able to generate integrity (hash) values if either shasum or openssl utilities are missing; if you don’t already have them installed, use homebrew or similar to install them or make sure they are correctly linked to `/usr/bin` | `/usr/local/bin system` directories depending upon your operating system

## EXAMPLES!
See the example apps in the example folder

## MORE INFORMATION!
- Read the docs: https://docs.spartan-security.io/
- Ask a question: @darkmsph1t => Twitter
- Submit an issue: [here](https://github.com/darkmsph1t/_spartan/issues)
