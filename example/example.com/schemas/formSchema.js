'use strict'

const registrationFormSchema = {
  method: 'post',
  fields: {
    username: {
      type: 'text',
      label: 'Username',
      validation: {
        required: true,
        minLen: 3,
        maxLen: 20
      }
    },
    email: {
      type: 'text',
      label: 'Email',
      validation: {
        required: true,
        minLen: 3
      }
    },
    password: {
      type: 'password',
      label: 'Password',
      validation: {
        required: true
      }
    },
    confirm: {
      type: 'password',
      label: 'Confirm Password',
      validation: {
        required: true,
        matches: '/password/'
      }
    }
  },
  action: '/test',
  submit: 'Submit'
}

const loginFormSchema = {
  method: 'post',
  fields: {
    email: {
      type: 'text',
      label: 'Email',
      validation: {
        required: true
      }
    },
    password: {
      type: 'password',
      label: 'Password',
      validation: {
        required: true
      }
    }
  },
  action: '/login',
  submit: 'Login!'
}

module.exports = {
  registerRules: registrationFormSchema,
  loginRules: loginFormSchema
}
