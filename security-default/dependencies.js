'use strict'
    let gulp = require('gulp')
    let { spawn } = require('child_process')
    /* this module is designed and written to identify vulnerabilities associated with application dependencies. The most opportune time to discover these vulnerabilities is PRIOR to application deployment (e.g. as part of your CI/CD pipeline) as such, this module utilizes `synk` for this purpose (with the `synk test` command ideally included early in the package.json test parameter). Assuming you have already installed the synk module and signed up for an account, the following tasks can be included in your gulpfile OR run as a separate gulpfile by using `gulp --gulpfile <path to this file>` at the command line
    */

    gulp.task('synk_auth', function (err, end) {
      if (err) return err
      spawn('snyk', ['auth'])
      end()
    })
    gulp.task('snyk_test', function (err, done) {
      if (err) return err
      spawn('synk', ['test'])
      done()
    })
    gulp.task('snyk_wizard', function (err, complete) {
      if (err) return err
      spawn('synk', ['wizard'])
      complete()
    })
    gulp.task('default', gulp.series(('synk_auth', 'synk_test', 'snyk_wizard'), function (err, done) {
      if (err) return err
      console.log('Application Dependency Check Complete!')
      done()
    }))