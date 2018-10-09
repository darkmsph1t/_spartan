## THIS. IS.\_SPARTAN!
node application to package &amp; configure common security middleware into your application => returns a policy file and boilerplate code

## QUICK START!
**\_installation**
Installing \_spartan is straightforward:
    1. First install the utility: `$ npm install -g spartan-shield`
       * Note : this assumes you have already built your app (and package.json) with `npm init`
    1. Next, invoke \_spartan from the command line with options: `$ _spartan [keywords][flags][options]`

1. **\_keywords**
    * There's really only one keyword: `init`. This will run the configuration wizard, unless you also use the `-y | -yes` flag to just accept the defaults and use the canned policy like this: `$ _spartan init -y` OR `$ _spartan init -yes`
1. **\_flags**
    * `-D, --default` : builds a preconfigured, default security policy and `security.js`. Word of warning that the default policy is fairly strict, so you may need to adjust it so it works for you
    * `-f, --force` : force a complete regeneration of the boilerplate code defined in `security.js`. Typically used after making a manual adjustment to the security.json file.
    * `-u, -update` : updates the latest policy as defined in security.json (see notes below on `security.js`)
    * `--no-overwrite` : creates a new policy and `security.js` file without overwriting the previous files. The filename will have the policy number appended.
    * `--del, --delete` : deletes the most recent security.json _**AND**_ the security.js files. It _does not_ remove any of the dependencies from `package.json`, **unless** it is run with the `-force` flag like this: `$ _spartan -f delete`
    * `set-as-default` : sets the latest policy as the default. Any future policies generated with the default option will reference this policy.
    * `-R, --reset-default` : Returns the default policy to factory settings

### Some words about `security.js`
1. **\_updates** As previously stated, `security.js` is the actual boilerplate code that is generated once you configure your security policy (`security.json`). Making updates to the security policy directly _will not_ translate to updates to the security.js file, and vice versa.
    1. If you _want_ policy updates to flow to the code, you'll need to run `_spartan -u | --update`. This will take you _back_ into the questionnaire (or the section you specified in the command line argument). Once complete, it will completely overwrite `security.js` with a new version reflecting the updated policy configuration.
    1. Alternatively, you can also run `_spartan -f | --force` _after_ updating the policy directly. \_spartan will parse `security.json` and will overwrite the existing `security.js` file with a new version reflecting the most current policy.

## EXAMPLES!
See the example app in the example folder

## KNOWN ISSUES & ASSUMPTIONS
- There's some wonkiness installing on Linux using the -g flag as access to `/usr/bin/` requires elevated permissions. You should still be able to install and run it locally without the global flag
- Be careful about making policy updates while you're app is running. This will really bite if you're using nodemon
- You'll need to create a `.env` file if you're going to use the secrets management module, otherwise, be sure to disable this module altogether in the policy.
