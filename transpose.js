'use strict'

/* ---------------------------POLICY SECTIONS------------------------------------------ */
function sbAccess (obj, tmp) {
  if (obj.type === 'API') {
    setValue(tmp.accessControlsPolicy, 'authenticationPolicy', 'supportedMethods', ['jwt'])
  }
  if (obj.exposure) {
    // Access Controls
    setValue(tmp.accessControlsPolicy, 'passwords', 'minLen', 12)
    setValue(tmp.accessControlsPolicy, 'passwords', 'attempts', 3)
    setValue(tmp.accessControlsPolicy, 'authenticationPolicy', 'mfaRequired', true)
    setValue(tmp.accessControlsPolicy, 'lockout', 'tarpitDefault', (5 * 60 * 1000))
    setValue(tmp.accessControlsPolicy, 'authorization', 'authorizationRequired', true)
    setValue(tmp.accessControlsPolicy, 'rbacPolicy', 'roles', ['user', 'admin'])
  } else {
    setValue(tmp.accessControlsPolicy, 'passwords', 'minLen', 8)
    setValue(tmp.accessControlsPolicy, 'passwords', 'attempts', 5)
    setValue(tmp.accessControlsPolicy, 'authenticationPolicy', 'mfaRequired', false)
    setValue(tmp.accessControlsPolicy, 'passwords', 'expires', 7776000)
    setValue(tmp.accessControlsPolicy, 'authorization', 'authorizationRequired', true)
    setValue(tmp.accessControlsPolicy, 'rbacPolicy', 'roles', ['user', 'admin'])
  }
}

function sbCors (obj, tmp) {
  // securityHeaders first
  if (obj.type === 'Embedded/IoT (Controller)') {
    var zing = tmp.securityHeaders.config.csp.directives
    for (var h in zing) {
      if (h === 'default-src') {
        setValue(tmp.securityHeaders, 'directives', 'default-src', ["'self'"])
      } else {
        setValue(tmp.securityHeaders, 'directives', h, false)
      }
    }
    setValue(tmp.resourceSharingPolicy.corsSettings, 'preflightRequests', 'onMethod', [])
    setValue(tmp.resourceSharingPolicy.corsSettings, 'preflightRequests', 'onHeader', [])
    setValue(tmp.resourceSharingPolicy.corsSettings, 'preflightRequests', 'maxAge', undefined)
    for (var alf in tmp.resourceSharingPolicy.corsSettings.config.responseHeaders) {
      setValue(tmp.resourceSharingPolicy.corsSettings, 'responseHeaders', alf, undefined)
    }
  } else {
    const result = []
    for (var k in obj.contentSources) {
      setValue(tmp.securityHeaders, 'directives', k, obj.contentSources[k])
      var bloop = Object.values(obj.contentSources[k])
      for (var i = 0; i <= bloop.length; i++) {
        if (bloop[i] === 'self' || bloop[i] === 'none' || bloop[i] === null) {
          // console.log("found : " + bloop[i]);
        } else {
          result.push(bloop[i])
        }
      }
    }
    setValue(tmp.resourceSharingPolicy, 'corsSettings', 'enabled', true)
    setValue(tmp.resourceSharingPolicy, 'config', 'whitelist', result)
  }
}
function sbSessions (obj, tmp) {
  if (obj.exposure) {
    // idle time
    if (obj.type === 'Desktop') {
      setValue(tmp.sessionPolicy, 'duration', 'idle', (15 * 60))
    } else if (obj.type === 'Web' || obj.type === 'Mobile') { setValue(tmp.sessionPolicy, 'duration', 'idle', (5 * 60)) } else if (obj.type === 'Kiosk') { setValue(tmp.sessionPolicy, 'duration', 'idle', (2 * 60)) } else { setValue(tmp.sessionPolicy, 'duration', 'idle', (1 * 60)) }
  } else {
    // id
    setValue(tmp.sessionPolicy, 'id', 'length', 64)
    // TTL
    setValue(tmp.sessionPolicy, 'duration', 'ttl', (60 * 60))
    // idle time
    if (obj.type === 'Desktop' || obj.type === 'Web' || obj.type === 'Mobile') { setValue(tmp.sessionPolicy, 'duration', 'idle', (15 * 60)) } else if (obj.type === 'Kiosk') { setValue(tmp.sessionPolicy, 'duration', 'idle', (5 * 60)) } else { setValue(tmp.sessionPolicy, 'duration', 'idle', (2 * 60)) }
    // cookies
    setValue(tmp.sessionPolicy, 'cookies', 'httpOnly', false)
    setValue(tmp.sessionPolicy, 'cookies', 'secure', false)
    setValue(tmp.sessionPolicy, 'cookies', 'sameSite', false)

    // automatic automaticRenewal
    if (obj.type === 'Desktop') {
      setValue(tmp.sessionPolicy, 'duration', 'automaticRenewal', true)
    }
    // csrfSettings
    setValue(tmp.sessionPolicy, 'csrfSettings', 'secretLength', 64)
  }
  setValue(tmp.sessionPolicy, 'duration', 'ttl', obj.sessionLength)
  setValue(tmp.sessionPolicy, 'cookies', 'maxAge', (obj.sessionLength * 1000))
}

function sbForms (obj, tmp) {
  setValue(tmp.formProtection, 'config', 'autocompleteAllowed', false)
  setValue(tmp.formProtection, 'config', 'acceptJsonContent', true)
  setValue(tmp.formProtection, 'config', 'allowMethodOverride', false)
}

function sbCache (obj, tmp) {
  // var cache = tmp.securityHeaders.caching.cacheControl // <-- I'm not doing anything with this variable. I need to populate max-age directive with the cache TTL
  if (!obj.exposure) {
    if (obj.type === 'Desktop' || obj.type === 'Mobile') {
      setValue(tmp.securityHeaders, 'caching', 'cacheControl', ['private', 'max-age=2592000'])
      setValue(tmp.securityHeaders, 'caching', 'pragma', 'private')
    } else if (obj.type === 'Web') {
      setValue(tmp.securityHeaders, 'caching', 'cacheControl', ['private', 'max-age=1296000'])
      setValue(tmp.securityHeaders, 'caching', 'pragma', 'private')
    } else {
      setValue(tmp.securityHeaders, 'caching', 'cacheControl', ['no-cache', 'no-store', 'no-transform', 'must-revalidate', 'max-age=0'])
    }
    setValue(tmp.securityHeaders, 'eTags', 'strength', 'weak')
    setValue(tmp.securityHeaders, 'caching', 'vary', 'none')
  }
}
/// ///////////////////////////////SET VALUE/////////////////////////////////////
function setValue (obj, key, subkey, value) {
  for (var k in obj) {
    if (k !== key) {
      if (typeof obj[k] === 'object') {
        setValue(obj[k], key, subkey, value)
      } else {
        // console.log("value of " + obj[k] + " is not an object");
      }
    } else {
      for (var j in obj[k]) {
        if (j === subkey) {
          obj[k][j] = value
          // console.log(obj[k][j]);
        }
      }
    }
  }
  return obj
}

function transformer (ans, pol) {
  // Administrative
  pol.applicationType = ans.type
  pol.internetFacing = ans.exposure
  pol.deployment = ans.deployment
  if (ans.hostname) {
    pol.hostname = ans.hostname
  } else {
    pol.hostname = 'localhost'
  }
  // App Dependencies
  if (!ans.exposure) {
    setValue(pol, 'appDependencies', 'auditOptions', [])
    setValue(pol, 'appDependencies', 'autoFix', null)
    setValue(pol, 'appDependencies', 'pathToReport', null)
    setValue(pol.resourceSharingPolicy, 'corsSettings', 'enabled', false)
  }

  // Access Controls
  if (!ans.access) {
    if (ans.type === 'Web' || ans.type === 'API') {
      console.log('Access Control Policy cannot be disabled for this application type or exposure, so the default settings have been added')
      ans.access = true
      sbAccess(ans, pol)
    } else {
      pol.accessControlsPolicy.enabled = false
      pol.accessControlsPolicy.compensatingControl = true
      setValue(pol.accessControlsPolicy, 'authenticationPolicy', 'authenticationRequired', false)
      setValue(pol.accessControlsPolicy, 'authenticationPolicy', 'supportedMethods', [])
      setValue(pol.accessControlsPolicy.authenticationPolicy, 'passwords', 'minLength', null)
      setValue(pol.accessControlsPolicy.authenticationPolicy, 'passwords', 'expires', null)
      setValue(pol.accessControlsPolicy.authenticationPolicy, 'passwords', 'supportedHashes', [])
      setValue(pol.accessControlsPolicy.authenticationPolicy.passwords, 'lockout', 'attempts', null)
      setValue(pol.accessControlsPolicy.authenticationPolicy.passwords, 'lockout', 'automaticReset', null)
      setValue(pol.accessControlsPolicy.authenticationPolicy.passwords, 'lockout', 'tarpitDefault', null)
      setValue(pol.accessControlsPolicy, 'authenticationPolicy', 'mfaRequired', null)
      setValue(pol.accessControlsPolicy, 'authorization', 'authorizationRequired', false)
      setValue(pol.accessControlsPolicy, 'authorization', 'supportedTypes', [])
      setValue(pol.accessControlsPolicy.authorization, 'rbacPolicy', 'roles', [])
      setValue(pol.accessControlsPolicy.authorization, 'rbacPolicy', 'permissions', [])
    }
  } else {
    sbAccess(ans, pol)
  }
  // Session Management
  if (ans.sessions !== 'User sessions have a set timeout') {
    pol.sessionPolicy.enabled = false
    pol.sessionPolicy.compensatingControl = true
    setValue(pol.sessionPolicy.config, 'id', 'length', null)
    setValue(pol.sessionPolicy.config, 'id', 'entropy', null)
    setValue(pol.sessionPolicy.config, 'id', 'invalidOnLogout', null)
    setValue(pol.sessionPolicy.config, 'id', 'regenerateOnAuth', null)
    setValue(pol.sessionPolicy.config, 'id', 'forceLogoutOnWindowClose', null)
    setValue(pol.sessionPolicy.config, 'duration', 'idle', null)
    setValue(pol.sessionPolicy.config, 'duration', 'ttl', null)
    setValue(pol.sessionPolicy.config, 'duration', 'automaticRenewal', null)
    setValue(pol.sessionPolicy.config, 'cookies', 'prefixes', [])
    setValue(pol.sessionPolicy.config, 'cookies', 'maxAge', null)
    setValue(pol.sessionPolicy.config, 'cookies', 'httpOnly', null)
    setValue(pol.sessionPolicy.config, 'cookies', 'secure', null)
    setValue(pol.sessionPolicy.config, 'cookies', 'sameSite', null)
    setValue(pol.sessionPolicy.config, 'cookies', 'domain', null)
    setValue(pol.sessionPolicy.config, 'cookies', 'path', null)
    setValue(pol.sessionPolicy.config, 'csrfSettings', 'secretLength', null)
    setValue(pol.sessionPolicy.config, 'csrfSettings', 'saltLength', null)
    setValue(pol.sessionPolicy.config, 'csrfSettings', 'ignoreMethods', [])
    setValue(pol.sessionPolicy.config, 'csrfSettings', 'allowHiddenToken', null)
    setValue(pol.sessionPolicy.config, 'csrfSettings', 'validateToken', null)
    setValue(pol.sessionPolicy, 'config', 'concurrentLogins', null)
  } else {
    sbSessions(ans, pol)
  }
  // Forms
  if (!ans.forms) {
    pol.formProtection.enabled = false
    pol.formProtection.compensatingControl = true
    setValue(pol.formProtection, 'config', 'autocompleteAllowed', null)
    setValue(pol.formProtection, 'config', 'acceptJsonContent', null)
    setValue(pol.formProtection, 'config', 'allowMethodOverride', null)
    setValue(pol.securityHeaders, 'sandbox', 'allowForms', false)
  } else {
    sbForms(ans, pol)
  }
  // Security headers & Resource Sharing
  if (ans.content !== 'Some of the data and content comes from sources that I don\'t own or control') {
    for (var l in pol.securityHeaders.config.csp.directives) {
      setValue(pol.securityHeaders.config.csp, 'directives', l, ["\'self\'"])
    }
    setValue(pol.resourceSharingPolicy, 'corsSettings', 'enabled', false)
    setValue(pol.resourceSharingPolicy.corsSettings, 'config', 'whitelist', ['same-origin'])
    setValue(pol.resourceSharingPolicy.corsSettings.config, 'preflightRequests', 'onMethod', [])
    setValue(pol.resourceSharingPolicy.corsSettings.config, 'preflightRequests', 'onHeader', [])
    setValue(pol.resourceSharingPolicy.corsSettings.config, 'preflightRequests', 'maxAge', null)
    setValue(pol.resourceSharingPolicy.corsSettings.config, 'responseHeaders', 'allowCredentials', null)
    setValue(pol.resourceSharingPolicy.corsSettings.config, 'responseHeaders', 'validateHeaders', null)
  } else {
    sbCors(ans, pol)
  }
  // connections
  if (!ans.secureTransport) {
    pol.connectionPolicy.enabled = false
    pol.connectionPolicy.compensatingControl = true
    setValue(pol, 'connectionPolicy', 'redirectSecure', false)
    setValue(pol, 'connectionPolicy', 'rejectWeakCiphers', false)
    setValue(pol, 'connectionPolicy', 'rejectInsecureTLS', false)
    setValue(pol, 'connectionPolicy', 'forceHttps', false)
    setValue(pol.securityHeaders.config, 'strictTransportSecurity', 'enabled', false)
    setValue(pol.securityHeaders.config, 'strictTransportSecurity', 'includeSubDomains', null)
    setValue(pol.securityHeaders.config, 'strictTransportSecurity', 'preload', null)
    setValue(pol.securityHeaders.config, 'strictTransportSecurity', 'maxAge', null)
  }
  // Cache Strategy
  if (!ans.cacheStrategy) {
    pol.securityHeaders.caching.enabled = false
    pol.securityHeaders.caching.compensatingControl = true
    setValue(pol.securityHeaders, 'caching', 'routeOverload', null)
    setValue(pol.securityHeaders, 'caching', 'cacheControl', [])
    setValue(pol.securityHeaders, 'caching', 'pragma', null)
    setValue(pol.securityHeaders.caching, 'eTags', 'enabled', false)
    setValue(pol.securityHeaders.caching, 'eTags', 'strength', null)
    setValue(pol.securityHeaders, 'caching', 'vary', [])
  } else {
    sbCache(ans, pol)
  }
  // Logging
  setValue(pol.loggingPolicy, 'logCollection', 'storage', ans.logging)
  return pol
}
module.exports.transformer = transformer
