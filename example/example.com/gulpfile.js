'use strict'
var gulp = require('gulp')

gulp.task('hello', function (end) {
  console.log('Hello!')
  end()
})
gulp.task('default', gulp.series('hello', function (done) {
  console.log('This is the default task')
  done()
}))
