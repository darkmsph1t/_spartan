'use strict'
// required middleware
let express = require('express')
let engines = require('consolidate')
let expressFileUpload = require('express-fileupload')
let bodyParser = require('body-parser')
let cookieParser = require('cookie-parser')
// local modules and variables
const security = require('./security')
let sessionizer = security.sessions.sessioner
const csrf = require('csurf')
let cookieMaker = security.sessions.cookieMaker
const User = security.auth.model
const cors = security.cors
const cache = require('./security').cache
// const { loginRules } = require('./schemas/formSchema')
// application plumbing
const database = require('./security').database
let secureConnection = security.connections.secureServer
let redirectSecure = security.connections.redirectHttp
// connect to the db
database()

let app = express()
app.use(sessionizer())
app.engine('pug', engines.pug)
app.set('view engine', 'pug')
app.set('views', './views')
// app.use(bodyParser.json({
//   type: ['json', 'application/cspviolations']
// }))
app.use(express.json())
app.use(express.urlencoded({
  extended: true
}))
const csrfMiddleware = csrf({
  cookie: true
})
app.use(cookieParser())
app.use(csrfMiddleware)
app.use(cors())
app.use(security.headers({ csp: true, cdp: true, sts: { usePolicy: true }, hidePower: { setTo: 'Your Mom\'s House' } }))

app.get('/', function (request, response) {
  let cacheHeaders = cache()
  // response.set(cacheHeaders)
  response.render('index')
})
app.post('/entry', function (request, response) {
  console.log(`Message received: ${request.body.message}`)
  response.send(`CSRF token used: ${request.body._csrf}, Message received: ${request.body.message}`)
})

app.get('/register', function (request, response, next) {
  response.render('register')
})
app.post('/register', function (request, response, next) {
  if (request.body.username && request.body.email && request.body.password && request.body.confirm) {
    if (request.body.password !== request.body.confirm) {
      let err = new Error('Passwords Don\'t Match')
      err.status = 400
      next(err)
    }
    let uData = new User({
      username: request.body.username,
      email: request.body.email,
      password: request.body.password
    })
    uData.save(function (err, user) {
      if (err) return next(err)
      else {
        app.locals.username = request.body.username
        request.session.userId = user._id
        response.redirect('/thanks')
      }
    })
  } else {
    let err = new Error('All Fields Are Required!')
    err.status = 400
    next(err)
  }
})
app.get('/thanks', function (request, response, next) {
  let options = {
    name: 'floopy',
    value: 1928347,
    options: { expires: new Date(Date.now() + 900000), path: '/' }
  }
  cookieMaker(request, response, options, function (err) {
    if (err) {
      next(err)
    } else {
      response.send(`Thanks for registering ${app.locals.username}.`)
    }
  })
})
app.get('/login', function (request, response) {
  let loginForm = security.forms
  // should also include some form parameters to ensure that no one is overloading the field
  response.send(` <h1>Login</h1> <form action="/login" autocomplete="${loginForm(request).autocomplete}" method="post">
                  <div> <label for="email">Email</label>
                  <input id="email" name="email" type="text" /></div>
                  <div> <label for="password">Password</label>
                  <input id="password" name="password" type="password" /></div>
                  <input type="submit" value="Submit" /><input type="hidden" name="_csrf" value="${request.csrfToken()}" />
                  </form>`)
  // response.render('login.ejs')
})
app.post('/login', function (request, response, next) {
  // check to see if the user is already authenticated
  // if (request.session && request.body.email) {
  //   response.redirect('/profile')
  // } else {
  if (request.body.password && request.body.email) {
    // authenticate
    User.getAuthenticated(request.body.email, request.body.password, function (err, user, reason) {
      if (err) {
        next(err)
      }
      if (!user) {
        let error = new Error('No such user')
        error.status = 401
        next(error)
      }
      if (user) {
        request.session.userId = user._id
        return response.redirect('/profile')
      }
    })
  } else {
    let error = new Error('Email and password are required to authenticate')
    error.status = 401
    next(error)
  }
  // }
})
app.get('/profile', function (request, response, next) {
  if (!request.session.userId) {
    let err = new Error('You need to be logged in to access this page')
    err.status = 403
    next(err)
  } else {
    User.findById(request.session.userId, function (error, user) {
      if (error) return next(error)
      else return response.send(`Welcome back, ${user.username}! We missed you!`)
    })
  }
})
app.get('/logout', function (request, response, next) {
  if (request.session) {
    request.session.destroy(function (err) {
      if (err) return next(err)
      else {
        response.redirect('/')
      }
    })
  }
})
app.get('/cspviolations', function (request, response, next) {
  if (request.body) {
    response.json({ 'CSP Violation: ': request.body })
  } else {
    response.json({ 'CSP Violation: ': 'No data received!' })
  }
  response.status(204).end()
  next()
})
app.post('/cspviolations', function (request, response, next) {
  if (request.body) {
    response.json({ 'CSP Violation: ': request.body })
  } else {
    response.json({ 'CSP Violation: ': 'No data received!' })
  }
  response.status(204).end()
})
redirectSecure()
secureConnection(app, function (request, response) {
  console.log('I\'m listening...')
})
