'use strict'
var gulp = require('gulp')
var dependencyCheck = require('security/dependencies')

gulp.task('dependency-check', function (end) {
  dependencyCheck()
  end()
})
// gulp.task('default', gulp.series('hello', function (done) {
//   console.log('This is the default task')
//   done()
// }))
