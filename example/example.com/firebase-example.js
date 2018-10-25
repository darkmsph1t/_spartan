'use strict'
let express = require('express')
let bodyParser = require('body-parser')
let security = require('./security')
let { secureServer, redirectHttp } = security.connections
let headers = security.headers
let cache = security.cache
let auth = require('./security/fire_auth')

let app = express()
app.use(bodyParser.json({
  type: ['json', 'application/cspviolations']
}))
app.use(express.json())
app.use(express.urlencoded({
  extended: true
}))
app.use(headers.setHeaders({ csp: true, hidePower: false, sts: { usePolicy: true } }))
app.get('/', function (request, response, next) {
  let cacheHeaders = cache()
  response.set(cacheHeaders)
  response.render('index.ejs')
})

app.get('/register', function (request, response, next) {
  response.render('register.ejs')
})

app.post('/register', function (request, response, next) {
  auth('firebase',
    { register: {
      username: request.body.username,
      email: request.body.email,
      password: request.body.password
    } }).then(value => {
    if (value instanceof Error) {
      next(value)
    } else {
      app.locals.username = value.ur.displayName
      response.redirect('/thanks')
    }
  }).catch(err => {
    if (err) {
      console.log(err)
      next(err)
    }
  })
})
app.get('/thanks', function (request, response, next) {
  let date = new Date()
  console.log(`New user ${app.locals.username} registered ${date}`)
  response.send(`Thanks for registering ${app.locals.username}!`)
})
app.get('/login', function (request, response, next) {
  response.render('login.ejs')
})
app.post('/login', function (request, response, next) {
  auth('firebase', { login: { email: request.body.email, password: request.body.password } }).then(value => {
    if (value instanceof Error || value === undefined) {
      next(value)
    } else {
      app.locals.email = request.body.email
      app.locals.userData = value
      response.redirect('/profile')
    }
  }).catch(err => {
    if (err) {
      console.log(err)
      next(err)
    }
  })
})
app.get('/forgotPassword', function (request, response, next) {
  response.render('forgot.ejs')
})
app.post('/forgotPassword', function (request, response, next) {
  auth('firebase', { resetPassword: { email: request.body.email } }).then(value => {
    if (value instanceof Error) {
      next(value)
    } else {
      app.locals.email = request.body.email
      response.redirect('/login')
    }
  }).catch(err => {
    if (err) {
      next(err)
    }
  })
})
app.get('/reset', function (request, response, next) {
  response.render('reset.ejs')
})
app.post('/reset', function (request, response, next) {
  auth('firebase', { changePassword: { old: request.body.old, new: request.body.new } }).then(value => {
    if (value instanceof Error) {
      next(value)
    }
    if (value === undefined) {
      let error = new Error(`Problem changing password for user ${app.locals.email}`)
      error.status = 401
      next(error)
    } else {
      // console.log(value)
      response.redirect('/profile')
    }
  }).catch(err => { next(err) })
})
app.get('/profile', function (request, response, next) {
  response.send(`Welcome Back ${app.locals.email}! <p>
  Change Your Password <a href="/reset"> Reset Password </a></p>`)
})
app.get('/logout', function (request, response, next) {
  auth('firebase', { logout: true }).then(value => {
    if (value instanceof Error) {
      next(value)
    } else {
      console.log(value)
      response.redirect('/')
    }
  }).catch(err => {
    if (err) {
      next(err)
    }
  })
})
redirectHttp()
secureServer(app, function (request, response) {
  console.log('I\'m listening')
})
