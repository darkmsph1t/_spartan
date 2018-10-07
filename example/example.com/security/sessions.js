'use strict'
const security = require('../security')
const session = require('express-session')
let MongoStore = require('connect-mongo')(session)
// const secJson = require('../security.json')
// const csrf = require('csurf')

// this module is concerned with the set up, tear down and protection of sessions
module.exports = function sessioner (app) {
  session.Session.prototype.login = function (user, callback) {
    const request = this.request
    request.session.regenerate(function (err) {
      if (err) {
        callback(err)
      }
    })
  }
  app.use(session({
    secret: security.secrets.fetchSecret('SESSION_SECRET'),
    resave: true,
    saveUninitialized: false,
    cookie: {
      path: '/',
      httpOnly: true,
      secure: true,
      maxAge: 6000
    },
    store: new MongoStore({
      mongooseConnection: security.database,
      ttl: (600)
    }),
    name: 'spartan'
  }))
}
/* ---------------------------------------- set-up ---------------------------------------------- */

/* --------------------------------------- tear-down -------------------------------------------- */

/* ------------------------------------------ CSRF ---------------------------------------------- */
function csrfKiller () {}

module.exports = {
  csrf: csrfKiller()
}
