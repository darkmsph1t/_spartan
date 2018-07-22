'use strict';
var fs = require("fs");
var uniqid = require('uniqid');


function writePolicy(input){
  var tmp = {};
  /* Admin Tasks
  - create policy
  - pull package name from package.json
  */
  tmp._policyID = uniqid();
  var pkg = fs.readFileSync("package.json");
  var pkgJson = JSON.parse(pkg);
  tmp.applicationName = pkgJson.name;
  /* Application Dependencies */
  tmp.appDependencies = {};
  tmp.appDependencies.enabled = true;
  tmp.appDependencies.compensatingControl = false;
  tmp.appDependencies.auditOptions = ["npm audit", "snyk"];
  tmp.appDependencies.autoFix = false;
  tmp.appDependencies.pathToReport = "/var/log/npm-audits/";
  /* Access Control */
  tmp.accessControlsPolicy = {
    "enabled" : true, "compensatingControl" : false
  };
  tmp.accessControlsPolicy.authenticationPolicy = {
    "authenticationRequired" : true,
    "supportedMethods" : ["uname/passwd", "oauth", "saml"],
    "passwords" : {
      "minLen" : 12,
      "expires?" : false,
      "supportedHashes" : ["bcrypt", "sha256", "md5"],
      "lockout" : {
          "attempts" : 3,
          "automaticReset" : false,
          "tarpitDefault" :  1000
      }}};
  tmp.accessControlsPolicy.authorization = {
    "authorizationRequired" : false,
    "supportedTypes" : ["flat", "rbac", "none"],
    "rbacPolicy" : {
      "roles" : ["user", "moderator", "admin"],
      "permissions" : ["read", "write", "create", "delete", "approve", "reject"]
  }};
  tmp.formProtection = {
    "enabled" : true,
    "compensatingControl" : false,
    "config" : {
      "autocompleteAllowed" : false,
      "acceptJsonContent" : true,
      "allowMethodOverride" : false,
      "csrfSettings" : {
        "secretLength" : 64,
        "saltLength" : 24,
        "ignoreMethods" : ["head", "options", "get"],
        "allowHiddenToken" : true,
        "validateToken" : true
      }
    }
  };
  tmp.sessionPolicy = {
    "enabled" : true,
    "compensatingControl" : false,
    "config" : {
      "id" : {
        "length" : 128,
        "entropy" : [64, "prng", "sha1"],
        "invalidOnLogout" : true,
        "regenerateOnAuth" : true,
        "forceLogoutOnWindowClose" : true
      },
      "duration" : {
        "idle" : 300000,
        "ttl" : 600000,
        "automaticRenewal" : false
      },
      "cookies": {
        "maxAge" : 600000*1000,
        "httpOnly" : true,
        "secure" : true,
        "sameSite" : true,
        "domain" : ["same-origin", "parent"],
        "path" :["same-origin", "parent"]
      },
      "concurrentLogins" : false
    }
  };
  tmp.securityHeaders = {
    "enabled" : true,
    "compensatingControl" : false,
    "config" : {
      "csp" : {
        "directives" : {
          "defaultSrc" : ["self"],
          "mediaSrc" : ["self"],
          "imageSrc" : ["self"],
          "fontSrc" : ["self"],
          "connectSrc" : ["self"],
          "objectSrc" : ["self"],
          "frameSrc" : ["self"],
          "frameAncestors" : ["none"],
          "workerSrc" : ["none"],
          "scriptSrc" : ["self"],
          "styleSrc" : ["self"],
          "upgradeInsecureRequests" : true,
          "blockAllMixedContent" : true,
          "subResourceIntegrity" : {
            "scripts" : false,
            "styles" : false
          },
          "sandbox" : {
            "setAll" : false,
            "allowPopUps" : true,
            "allowTopNavigation" : true,
            "allowSameOrigin" : true,
            "allowForms" : true,
            "allowPointerLock" : true,
            "allowScripts" : true
          },
          "reflectedXSS" : {
            "allow" : false,
            "block" : true,
            "filter" : false
          },
          "reportUri" : {
            "default" : "disabled",
            "uriLocation" : "/cspviolations",
            "port" : 3030
          }
        },
        "reportOnly" : true,
        "useNonce" : false,
        "useHash" : false
      },
      "mimeSettings" : {
        "mimeTypes" : ["text/html", "application/json", "image/jpg", "image/png"],
        "contentEncoding" : "gzip",
        "characterEncoding" : "utf-8",
        "xContentTypeOptions" : "nosniff"
      },
      "strictTransportSecurity" : {
        "enabled": true,
        "includeSubDomains": true,
        "preload" : false,
        "maxAge" : 31536000
      },
      "preventClickJacking" : true,
      "referrals" : {
        "enabled" : true,
        "options" : {
          "noReferer" : true,
          "noOnDowngrade" : false,
          "originOnly" : false,
          "originOnCross" : false,
          "unsafeUrl" : false
        },
      },
      "xssProtection" : {
        "enabled" : true,
        "mode" : [1, "block"],
      }
    },
    "caching" : {
      "enabled" : true,
      "routeOverload" : false,
      "cacheControl" : ["no-cache", "no-store", "no-transform", "must-revalidate", "max-age=0"],
      "pragma" : "no-cache",
      "eTags" : {
        "enabled" : true,
        "strength" : "strong"
      },
      "vary" : ["origin", "host", "referer"],
    }
  };
  tmp.contentValidationPolicy = {
    "enabled" : true,
    "compensatingControl" : false,
    "syntaxValidation" : {
        "checkLength" : true,
        "checkFormat" : true,
        "checkType" : true
      },
      "semanticValidation" : {
        "allowBlankValues" : false,
        "orderMakesSense?" : true,
        "valueInRange?" : true,
        "whitelistRequired" : ["cors", "csp", "headers", ""]
      },
      "sanitizeValues" : {
        "enableEncoding" : ["url", "body", "javascript", "html", "css"],
        "convertToType" : true
      },
    "blockOnFail" : true
  };
  tmp.dbSecurityPolicy = {
    "enabled" : true,
    "compensatingControl" : false,
    "config" : {
      "disableJsExecution" : true,
      "globalOperatorsDisabled" : true,
      "encryptBeforeStore" : true
    }
  };
  tmp.connectionPolicy = {
    "enabled" : true,
    "redirectSecure" : true,
    "rejectWeakCiphers" : true,
    "rejectInsecureTLS" : true,
    "forceHttps" : true,
  };
  tmp.resourceSharingPolicy = {
    "default" : "same-origin",
    "compensatingControl" : false,
    "corsSettings" : {
      "enabled" : false,
      "config" : {
        "preflightRequests" : {
          "onMethod" : ["put", "delete", "connect", "options", "trace", "patch"],
          "onHeader" : ["accept", "accept-language", "content-language", "dpr", "save-data", "viewpot-width", "width"],
          "maxAge" : 3600
        },
        "responseHeaders" : {
          "allowCredentials" : true,
          "validateHeaders" : ["origin", "allow-method","expose-headers"]
        }
      }
    }
  };
  tmp.loggingPolicy = {
    "enabled" : true,
    "compensatingControl" : false,
    "levels" : ["trace","info", "warn", "error", "fatal","debug", "verbose"],
    "logCollection" : {
      "storage" : "/var/log/${appName}/",
      "retentionPeriod" : 4,
      "port" : 5601
    },
    "analytics" : {
      "enabled" : false,
      "config" : {
        "host" : "localhost",
        "type" : "telegraf",
        "port" : 8125
        }
      }
  };
  console.log(tmp);
}
writePolicy();

module.exports.writePolicy = writePolicy;
