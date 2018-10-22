'use strict'
require('dotenv').config()
/* Pretty much, the only purpose of this file is to safely load environment variables.
   By default, will only load if the environment HAS NOT been identified as production (e.g. stage, dev, uat). To use this, module effectively, run `npm install dotenv--save` and create a .env file.
   BE SURE TO ADD THE .ENV FILE TO YOUR .GITIGNORE FILE
*/
function fetchSecret (variable) {
  if (process.env.NODE_ENV !== 'production') {
    require('dotenv').load()
    return process.env[variable]
  } else {
    let error = new Error(`Could not fetch variable ${ variable }.It is not available in this environment`)
    return error
  }
}

module.exports.fetchSecret = fetchSecret