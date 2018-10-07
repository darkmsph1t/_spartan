'use strict'
// required middleware
let express = require('express')
let bodyParser = require('body-parser')
let session = require('express-session')
let MongoStore = require('connect-mongo')(session)
// let csrf = require('csurf')
let cookieParser = require('cookie-parser')
// local modules and variables
const security = require('./security')
const User = security.auth.model
const cors = security.cors
const cache = require('./security').cache
const { registerRules, loginRules } = require('./schemas/formSchema')
// application plumbing
const database = require('./security').database
let secureConnection = security.connections.secureServer
let redirectSecure = security.connections.redirectHttp

// connect to the db
database()

// const csrfMiddleware = csrf({
//   cookie: true
// })
let app = express()
app.use(session({
  secret: security.secrets.fetchSecret('SESSION_SECRET'),
  resave: true,
  saveUninitialized: false,
  cookie: {
    path: '/',
    httpOnly: true,
    secure: true,
    sameSite: true,
    maxAge: 6000
  },
  // store: new MongoStore({
  //   mongooseConnection: database,
  //   ttl: (600)
  // }),
  name: 'spartan'
}))
app.use(bodyParser.json({
  type: ['json', 'application/cspviolations']
}))
app.use(express.json())
app.use(express.urlencoded({
  extended: true
}))
app.use(cookieParser())
// app.use(csrfMiddleware)
app.use(cors())
app.use(security.headers.setHeaders({ csp: true, cdp: true, sts: { usePolicy: true }, hidePower: { setTo: 'Your Mom\'s House' } }))

app.get('/', function (request, response) {
  let cacheHeaders = cache()
  response.set(cacheHeaders)
  // response.send(`
  //   <h1>Hello World</h1>
  //   <form action="/entry" method="POST">
  //     <div>
  //       <label for="message">Enter a message</label>
  //       <input id="message" name="message" type="text" />
  //     </div>
  //     <input type="submit" value="Submit" />
  //     <input type="hidden" name="_csrf" value="${request.csrfToken()}" />
  //   </form>
  // `)
  response.render('index.ejs')
})
app.post('/entry', function (request, response) {
  console.log(`Message received: ${request.body.message}`)
  response.send(`CSRF token used: ${request.body._csrf}, Message received: ${request.body.message}`)
})

app.get('/register', function (request, response) {
  let registrationForm = security.forms
  response.send(registrationForm(request).generateForm(registerRules))
  // response.render('register.ejs')
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
  response.send(`Thanks for registering ${app.locals.username}`)
})
app.get('/login', function (request, response) {
  let loginForm = security.forms
  // should also include some form parameters to ensure that no one is overloading the field
  response.send(loginForm(request).generateForm(loginRules))
  // response.render('login.ejs')
})
app.post('/login', function (request, response, next) {
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
})
app.get('/profile', function (request, response, next) {
  if (!request.session.userId) {
    let err = new Error('You need to be logged in to access this page')
    err.status = 403
    next(err)
  }
  User.findById(request.session.userId, function (error, user) {
    if (error) return next(error)
    else return response.send(`Welcome back, ${user.username}! We missed you!`)
  })
})
app.get('/logout', function (request, response, next) {
  if (request.session) {
    request.session.destroy(function (err) {
      if (err) return next(err)
      else return request.redirect('/')
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
