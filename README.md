# \_spartan
npm command line utility to package &amp; configure common security middleware into your application

## THIS. IS.\_SPARTAN.
1. You define and configure your application's security policy by answering a series of questions about the app
1. We generate a `security.json` file which essentially serves as the technical specification of your security policy. This file ultimately serves three purposes:
  *  It is the basis upon which the `security.js` file is created. More on that below.
  * It _is_ your application's security policy. This is a really quick, easy thing you can show to auditors or push into your org's downstream auditing engines.
  * It is the entry-level requirement to use with \_phlanax. I won't belabor the point here, but if your app is part of a larger web application _platform_, \_phlanax ensures that all of the other apps in the platform are operating at a common security level.
1. We parse the policy file and generate `security.js` which contains the boilerplate code that you will actually wire up in your app.
1. We update the `package.json` file with any/all modules required to make this whole thing work.

## USAGE
1. **\_installation**
Installing \_spartan is straightforward:
  1. First install the utility: `$ npm i _spartan -g`
  1. Next, invoke \_spartan from the command line with options: `$ _spartan [keywords][flags][options]`
1. **\_keywords**
  * There's really only one keyword: `init`. This will run the configuration wizard, unless you also use the `-y | -yes` flag to just accept the defaults and use the canned policy like this: `$ _spartan init -y` OR `$ _spartan init -yes`
1. **\_flags**
  * `-d | -default` : builds a preconfigured, default security policy and `security.js`. Word of warning that the default policy is fairly strict, so you may need to adjust it so it works for you
  * `-f | -force` : force a complete regeneration of the boilerplate code defined in `security.js`. Typically used after making a manual adjustment to the security.json file.
  * `u | -update` : updates the latest policy as defined in security.json (see notes below on `security.js`)
1. **\_options**
  * _update by section_ : admittedly, the questionnaire is kind of long. If you know what section you want to update, simply append the section name to the end of the update command like this: `$ _spartan -u 'cachePolicy'`. This will take you to the portion of the questionnaire which addresses this topic. Before you ask, yes, there's a PR in the works to be able to do direct updates from the command line.
  * `delete` : deletes the most recent security.json _**AND**_ the security.js files. It _does not_ remove any of the dependencies from `package.json`, **unless** it is run with the `-force` flag like this: `$ _spartan -f delete`   

### Some words about `security.js`
1. **\_updates** As previously stated, `security.js` is the actual boilerplate code that is generated once you configure your security policy (`security.json`). Making updates to the security policy directly _will not_ translate to updates to the security.js file, and vice versa.
  1. If you _want_ policy updates to flow to the code, you'll need to run `_spartan -u [ | section you want to update]`. This will take you _back_ into the questionnaire (or the section you specified in the command line argument). Once complete, it will completely overwrite `security.js` with a new version reflecting the updated policy configuration.
  1. Alternatively, you can also run `_spartan -f | -force` _after_ updating the policy directly. \_spartan will parse `security.json` and will overwrite the existing `security.js` file with a new version reflecting the most current policy.

## FAQ
1. _Can I write my own policy without going through the questionnaire?_
Sure. Just be sure to use the common template. `security.js` will only be generated based upon the existing format. Generation of `security.js` is an atomic process => if there's an error or typo, it _will not_ be generated at all.
1. _Where can I see errors or logs for \_spartan process?_
For the time being, logs are stored in the local directory. I'll eventually do a PR to offer a config.json file where this can be user specified. In the meantime, I suggest adding `_spartan_errors.log` to .gitignore
1. _Can I define multiple policies?_
Sure. For now, \_spartan will only generate `security.js` from **the most recent** policy. I _have_ been giving some thought to adding a `-r [policy_number]` option to allow \_spartan to regenerate `security.js` based upon the reference number in each policy.
1. _What if I want to use different modules than the ones added in during the policy spec phase?_
Do you boo. \_spartan was developed and tested to work with a handful of specific modules with known configuration options. If you want to add/modify/delete configuration options in your app, or if you want to utilize other middleware, feel free! Results may vary.  
