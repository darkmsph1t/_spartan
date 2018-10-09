# \_spartan
node application to package &amp; configure common security middleware into your application

## THIS. IS.\_SPARTAN!
1. You define and configure your application's security policy by answering a series of questions about the app
1. \_spartan generates a `security.json` file which essentially serves as the technical specification of your application's security policy. This file ultimately serves three purposes:
    * It is the basis upon which the `security.js` file is created. More on that below.
    * It _is_ your application's security policy. This is a really quick, easy thing you can show to auditors or push into your org's downstream auditing engines.
    * It is the entry-level requirement to use with `_phlanax`. I won't belabor the point here, but if your app is a microservice operating as part of a larger web application _platform_, \_phlanax ensures that all of the other apps in the platform are operating at a common security level.
1. We parse the policy file and generate `security.js` which contains the boilerplate code that you will actually wire up in your app.
1. We update the `package.json` file with any/all modules required to make this whole thing work. All you have to do is: `require($PATH/security.js)`

### THIS. IS. NOT.\_SPARTAN!
1. \_spartan is not intended to make your app completely 'breach proof'. After all, if your app's business logic is such that it creates or introduces a vulnerability, \_spartan will not be able to influence that. \_spartan _will_ allow your app to be built from a 'secure by default' baseline so that developers, architects and product owners can make _**deliberate, measurable**_ security risk decisions.  
1. While the security.json file serves as a great way to describe and _attest_ to your application's security policies, it _is not_ the only thing you need to have or present in order to pass an audit. Stay tuned for a PR that includes an audit-only role which will not only produce the security.json policy, but also the `.snyk` vulnerability report and a **basic** code review.  

## USAGE!
1. **\_installation**
Installing \_spartan is straightforward:
    1. First install the utility: `$ npm install -g spartan-shield`
       * Note : this assumes you have already built your app (and package.json) with `npm init`
    1. Next, invoke \_spartan from the command line with options: `$ _spartan [keywords][flags][options]`
1. **\_keywords**
    * There's really only one keyword: `init`. This will run the configuration wizard, unless you also use the `-y | -yes` flag to just accept the defaults and use the canned policy like this: `$ _spartan init -y` OR `$ _spartan init -yes`
1. **\_flags**
    * `-d | -default` : builds a preconfigured, default security policy and `security.js`. Word of warning that the default policy is fairly strict, so you may need to adjust it so it works for you
    * `-f | -force` : force a complete regeneration of the boilerplate code defined in `security.js`. Typically used after making a manual adjustment to the security.json file.
    * `-u | -update` : updates the latest policy as defined in security.json (see notes below on `security.js`)
    * `-n | -no-overwrite` : creates a new policy and `security.js` file without overwriting the previous files. The filename will have the policy number appended.
1. **\_options**
    * _update by section_ : admittedly, the wizard is kind of long. If you know what section you want to update, simply append the section name to the end of the update command like this: `$ _spartan -u 'cachePolicy'`. This will take you to the portion of the questionnaire which addresses this topic. Before you ask, yes, there's a PR in the works to be able to do direct updates from the command line.
    * `delete` : deletes the most recent security.json _**AND**_ the security.js files. It _does not_ remove any of the dependencies from `package.json`, **unless** it is run with the `-force` flag like this: `$ _spartan -f delete`
    * `set-as-default` : sets the latest policy as the default. Any future policies generated with the default option will reference this policy.

### Some words about `security.js`
1. **\_updates** As previously stated, `security.js` is the actual boilerplate code that is generated once you configure your security policy (`security.json`). Making updates to the security policy directly _will not_ translate to updates to the security.js file, and vice versa.
    1. If you _want_ policy updates to flow to the code, you'll need to run `_spartan -u [ | section you want to update]`. This will take you _back_ into the questionnaire (or the section you specified in the command line argument). Once complete, it will completely overwrite `security.js` with a new version reflecting the updated policy configuration.
    1. Alternatively, you can also run `_spartan -f | -force` _after_ updating the policy directly. \_spartan will parse `security.json` and will overwrite the existing `security.js` file with a new version reflecting the most current policy.

## EXAMPLES!

## FAQ!
1. _Can I write my own policy without going through the questionnaire?_
Sure. Just be sure to use the common template and leave the policy number component blank. `security.js` will only be generated based upon the existing format. Generation of `security.js` is an atomic process => if there's an error or typo, it _will not_ be generated at all. If the process is successful, a new policy number will be populated in the completed security.json file.
1. _Where can I see errors or logs for \_spartan processes?_
For the time being, logs are stored in the local directory. I'll eventually do a PR to offer a config.json file where this can be user specified. In the meantime, I suggest adding `_spartan_events.log` to .gitignore
1. _Can I define multiple policies?_
Sure. For now, \_spartan will only generate `security.js` from **the most recent** policy (according to the spartan event logs). I _have_ been giving some thought to adding a `-r [policy_number]` option to allow \_spartan to regenerate `security.js` based upon the reference number in each policy.
1. _What if I want to use different modules than the ones added in during the policy spec phase?_
Do you boo. \_spartan was developed and tested to work with a handful of specific modules with known configuration options. If you want to add/modify/delete configuration options in your app, or if you want to utilize other middleware, feel free! In this case, I would recommend disabling or removing \_spartan generated methods for the purposes of code clarity. Results may vary.
1. _Can I just arbitrarily change `security.json` without making any real changes to the code base?_
I mean, you can...but why? That kind of defeats the whole purpose. I would recommend running `_spartan -f` when you're done to regenerate security.js to avoid confusion down the line.
1. _If I decide later on to disable certain parts of the security policy, will this also be refelected in my main code base?_
Kinda. `security.js` will be regenerated and it will be missing the middleware from the disabled portions of the policy. If your code base references that missing middleware _anywhere_ you'll end up with a breaking error. As a general rule, anything you wire up, you'll need to be able to unwire. This was a purposeful design decision to encourage people to make policy changes with care/caution
1. _What's your problem with JWT?_
Not so much a _problem_ per se, but more of a concern with the ability to easily revoke JWTs in the event something goes awry. You're far awesomer than me if you want to build and implement your own revocation scheme for JWT in your application. I'd say if your app won't be internet-facing or doesn't have _any_ sensitive information to process or present back to users, then, sure, enjoy your JWT. I'm not planning on building any kind of support in for JWT policy configuration, though.
