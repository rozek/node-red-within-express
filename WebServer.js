/*******************************************************************************
*                                                                              *
*                  WebServer with embedded Node-RED Instance                   *
*                                                                              *
*******************************************************************************/

  const Version = '0.1.0'

  const fs     = require('fs')
  const path   = require('path')
  const crypto = require('crypto')
  const url    = require('url')
  const http   = require('http')
  const https  = require('https')

  const express = require('express')
  const RED     = require('node-red')

/**** Node-RED configuration ****/

  const REDSettings = {
    httpAdminRoot: '/.Node-RED/Editor',  // Node-RED Editor, must start with '/'
                                        // will only be served by primary domain
    httpNodeRoot:     '/',      // Node-RED "HTTP in" nodes, must start with '/'
    userDir:          './Node-RED',    // will be appended to "ConfigRoot" later
    flowFile:         'flows.json',                  // independent of host name
    credentialSecret: 'not-so-secret',
    flowFilePretty:   true,

    functionExternalModules: true,
    functionGlobalContext:   {},
  }

//------------------------------------------------------------------------------
//--                       Command-Line Argument Parser                       --
//------------------------------------------------------------------------------

/**** parsePortNumber ****/

  function parsePortNumber (Value) {
    Value = Value.trim()
    if (Value === '') { throw 'no <port-number> given' }

    let PortNumber = parseInt(Value,10)
    if (isNaN(PortNumber)) { throw 'illegal <port-number> given' }

    if ((PortNumber < 0) || (PortNumber > 65535)) {
      throw 'invalid <port-number> given'
    }

    return PortNumber
  }

/**** parsePBKDF2Iterations ****/

  function parsePBKDF2Iterations (Value) {
    Value = Value.trim()
    if (Value === '') { throw 'no PBKDF2 iteration <count> given' }

    let Count = parseInt(Value,10)
    if (isFinite(Count) && (Count > 0)) {
      return Count
    } else {
      throw 'invalid PBKDF2 iteration <count> given'
    }
  }

/**** parseDomain ****/

  function parseDomain (Value) {
    Value = Value.trim()
    if (Value === '') { throw 'no <domain> given' }

    if (/^[a-z][a-z0-9]*([-.][a-z][a-z0-9]*)+$/i.test(Value)) {
      return Value
    } else {
      throw 'invalid <domain> given (' + Value + ')'
    }
  }

/**** parseVirtualHosts ****/

  function parseVirtualHosts (Value) {
    Value = Value.trim()
    if (Value === '') { return [] }

    let DomainList = Value
      .replace(/\s*,\s*/g,',')               // eliminate white-space around ','
      .replace(/,,+/g,',')                 // reduce multiple consecutive commas
      .split(',')                                             // split at commas
    DomainList.forEach((Domain) => {
      if (/^[a-z][a-z0-9]*([-.][a-z][a-z0-9]*)+$/i.test(Domain)) {
        return Domain
      } else {
        throw 'invalid <domain> given (' + Domain + ')'
      }
    })

    return DomainList
  }

/**** parseTrustProxy ****/

  function parseTrustProxy (Value) {
    Value = Value.trim()
    switch (Value) {
      case '':      throw 'no <proxy> given'
      case 'true':  return true
      case 'false': return false
      default:
        if (/^[0-9]+$/.test(Value)) {
          return parseInt(Value,10)
        } else {
          return Value    // no further validations here, leave it up to Express
        }
    }
  }

  let Arguments = require('commander'), RootFolder, ConfigFolder, LogFolder

  Arguments
    .version(Version, '-v, --version')
    .usage('[options] [file-root [configuration-folder [log-folder]]]')
    .option('--server-port <port>', 'server port number', parsePortNumber)
    .option('--redirection-port <port>', 'redirection port number', parsePortNumber)
    .option('--proxy <proxy>', 'trusted proxy', parseTrustProxy)
    .option('--domain <domain>', '(primary) domain', parseDomain)
    .option('--virtual-hosts <virtual-hosts>', 'list of virtual hosts', parseVirtualHosts)
    .option('--allow-subdomains', 'map subdomains to subfolders')
    .option('--ignore-www', 'avoid separate "www." subdomain')
    .option('--cert-folder <folder>','folder with server certificate files')
    .option('--pbkdf2-iterations <count>', 'PBKDF2 iteration count', parsePBKDF2Iterations)
    .option('--log-format <format>', 'morgan-compatible log format')
    .arguments('<file-root> [configuration-folder [log-folder]]')
    .action(function (FileRoot, ConfigRoot, LogRoot) {
      RootFolder   = path.resolve(process.cwd(), FileRoot)
      ConfigFolder = ( ConfigRoot == null
        ? null
        : path.resolve(process.cwd(), ConfigFolder)
      )
      LogFolder = ( LogRoot == null
        ? null
        : path.resolve(process.cwd(), LogFolder)
      )
    })
    .parse(process.argv)

  const Options = Arguments.opts()
    const ServerPort      = Options.serverPort || 8443
    const RedirectionPort = Options.redirectionPort               // no default!
      if (ServerPort === RedirectionPort) {
        throw 'Invalid Argument: <server-port> and <redirection-port> must not be identical'
      }
    const behindProxy     = Options.proxy || false
    const primaryDomain   = Options.domain
    const virtualHosts    = Options.virtualHosts    || []
    const allowSubdomains = Options.allowSubdomains || false
      if (primaryDomain == null) {
        if (virtualHosts.length > 0) {
          throw '"--virtual-hosts" may only be used if a "--domain" is given'
        }

        if (allowSubdomains) {
          throw '"--allow-subdomains" may only be used if a "--domain" is given'
        }
      }

      if ((virtualHosts.length > 0) || allowSubdomains) {
        if ((primaryDomain != null) && (virtualHosts.indexOf(primaryDomain) < 0)) {
          virtualHosts.unshift(primaryDomain)
        }
      }
    const ignoreWWW        = (Options.ignoreWww == null ? true : Options.ignoreWww)
    const PBKDF2Iterations = Options.pbkdf2Iterations || 100000
    const LogFormat        = Options.logFormat        || 'common'
  const FileRoot   = RootFolder   || path.join(process.cwd(),'public')
  const ConfigRoot = ConfigFolder || process.cwd()
  const LogRoot    = LogFolder    || path.join(process.cwd(),'logs')

  const CERTFolder = Options.certFolder || (
    primaryDomain == null
    ? path.join(ConfigRoot,'certificates/localhost')
    : path.join(ConfigRoot,'certificates',primaryDomain)
  )

//------------------------------------------------------------------------------
//--                                  Helmet                                  --
//------------------------------------------------------------------------------

  const helmet = require('helmet')

  let ContentSecurityPolicies
  try {
    ContentSecurityPolicies = Object.assign(Object.create(null), JSON.parse(
      fs.readFileSync(path.join(ConfigRoot, 'ContentSecurityPolicies.json'), 'utf8')
    ))
  } catch (Signal) {
    console.error('could not load Content Security Policies',Signal)
    process.exit(1)
  }

  const configuredHelmet = helmet({
    contentSecurityPolicy: {
      directives: {
        ...helmet.contentSecurityPolicy.getDefaultDirectives(),
        ...ContentSecurityPolicies
      }
    }
  })

//------------------------------------------------------------------------------
//--                             Path Normalizer                              --
//------------------------------------------------------------------------------

  let EditorDomain = primaryDomain || virtualHosts[0] || ''   // Node-RED Editor

  function PathNormalizer (Request, Response, next) {
    let URLPath = url.parse(Request.url).pathname
    if (URLPath[0] !== '/') { URLPath = '/' + URLPath }

    let RootFolder = FileRoot
    if (virtualHosts.length > 0) {
      let virtualHost = Request.headers[':authority'] || Request.headers.host
      if (behindProxy && (Request.headers['x-forwarded-host'] != null)) {
        virtualHost = Request.headers['x-forwarded-host']
      }

      if (virtualHost == null) {                        // no virtual host given
        return Response.sendStatus(404)
      } else {
        virtualHost = virtualHost.replace(/:\d+$/,'')
      }

      Request.virtualHost = virtualHost; virtualHost = ''
        virtualHosts.forEach((Candidate) => {
          if (
            (Request.virtualHost === Candidate) ||
            allowSubdomains && Request.virtualHost.endsWith('.' + Candidate)
          ) {
            virtualHost = (
              ignoreWWW && (Request.virtualHost === 'www.' + Candidate)
              ? Candidate
              : Request.virtualHost
            )
          }
        })
      if (virtualHost === '') {       // the given virtual host is not supported
        return Response.sendStatus(404)
      }

    /**** Node-RED Editor does not like URL normalization ****/

      if (
        URLPath.startsWith(REDSettings.httpAdminRoot) &&
        (virtualHost === EditorDomain)
      ) { return next() }

    /**** but all other entry points have to ****/

      RootFolder = path.join(FileRoot, virtualHost) // host-specific root folder
      URLPath    = '/' + virtualHost + URLPath
    }

  /**** keep clients within their root folders ****/

    let FilePath = path.normalize(path.join(FileRoot,URLPath))
    if (FilePath.startsWith(RootFolder) && (FilePath !== RootFolder)) {
      Request.url = URLPath  // poor hack for getting host-specific root folders
    } else {
      Response.sendStatus(404)
    }

    return next()
  }

//------------------------------------------------------------------------------
//--                                   CORS                                   --
//------------------------------------------------------------------------------

  const cors = require('cors')

  let CORSRegistry
  try {
    CORSRegistry = JSON.parse(
      fs.readFileSync(path.join(ConfigRoot, 'sharedResources.json'), 'utf8')
    )

    for (let i = 0, l = CORSRegistry.length ; i< l; i++) {
      let Rule = CORSRegistry[i]
      Rule.PathPattern = new RegExp(Rule.PathPattern)
    }
  } catch (Signal) {
    console.error('could not load CORS registry',Signal)
    process.exit(1)
  }

  function validateCORS (Request, CallBack) {
    let URLPath = url.parse(Request.url).pathname
    if (URLPath[0] !== '/') { URLPath = '/' + URLPath }

    let Origin = (Request.header('Origin') || '')      // trim protocol and port
      .replace(/^[^:]+.\/\//,'').replace(/:\d+$/,'')

    for (let i = 0, l = CORSRegistry.length ; i < l; i++) {
      let Rule = CORSRegistry[i]
      if (Rule.PathPattern.test(URLPath)) {
        let allowSharing = (
          (Rule.OriginList == null) ||
          (Rule.OriginList.indexOf(Origin) >= 0)
        )
        return CallBack(null,{ origin:allowSharing })
      }
    }

    CallBack(null,{ origin:false })
  }

//------------------------------------------------------------------------------
//--                              Authentication                              --
//------------------------------------------------------------------------------

  const BasicAuth = require('basic-auth')

  let UserRegistry
  try {
    UserRegistry = Object.assign(Object.create(null), JSON.parse(
      fs.readFileSync(path.join(ConfigRoot, 'registeredUsers.json'), 'utf8')
    ))
  } catch (Signal) {
    console.error('could not load user registry',Signal)
    process.exit(1)
  }

  function authenticateUser (Request, Response, next) {
    function withAuthenticationFailure () {
      Response.set('WWW-Authenticate','Basic realm="' + Request.virtualHost + '"')
      return Response.sendStatus(401)
    }

    let Credentials = BasicAuth(Request)
    if (Credentials == null) { return withAuthenticationFailure() }

    let UserId   = Credentials.name
    let Password = Credentials.pass

    if (! (UserId in UserRegistry)) { return withAuthenticationFailure() }

    let UserSpecs = UserRegistry[UserId]
    if (UserSpecs.Password === Password) {              // internal optimization
      Request.authenticatedUser = UserId
      return next(Request,Response)
    }

    crypto.pbkdf2(
      Password, Buffer.from(UserSpecs.Salt,'hex'), PBKDF2Iterations, 64, 'sha512',
      function (Error, computedHash) {
        if (Error == null) {
          if (computedHash.toString('hex') === UserSpecs.Hash) {
            UserSpecs.Password = Password     // speeds up future auth. requests
            Request.authenticatedUser = UserId
            return next(Request,Response)
          }
        }
        return withAuthenticationFailure()
      }
    )
  }

//------------------------------------------------------------------------------
//--                           Node-RED Protection                            --
//------------------------------------------------------------------------------

  function protectNodeRED (Request, Response, next) {
    authenticateUser(Request, Response, (Request, Response) => {
      let authenticatedUser = Request.authenticatedUser
      let authorizedRoles = (
        authenticatedUser == null ? null : UserRegistry[authenticatedUser].Roles
      )
      if (
        Array.isArray(authorizedRoles) &&
        (authorizedRoles.indexOf('node-red') >= 0)
      ) {
        return next()
      } else {
        Response.set('WWW-Authenticate','Basic realm="' + Request.virtualHost + '"')
        return Response.sendStatus(401)
      }
    })
  }

//------------------------------------------------------------------------------
//--                          static File Protection                          --
//------------------------------------------------------------------------------

  let ProtectionRegistry
  try {
    ProtectionRegistry = Object.assign(Object.create(null), JSON.parse(
      fs.readFileSync(path.join(ConfigRoot, 'protectedFiles.json'), 'utf8')
    ))

    for (let PathPattern in ProtectionRegistry) {
      let UserList = ProtectionRegistry[PathPattern].trim().replace(/\s+/g,' ').split(' ')
      switch (UserList.length) {
        case 0: UserList = null; break
        case 1: if (UserList[0] === '*') { UserList = null }; break
      }

      ProtectionRegistry[PathPattern] = {
        PathPattern:   new RegExp(PathPattern),
        permittedUsers:UserList
      }
    }
  } catch (Signal) {
    console.error('could not load file protection registry',Signal)
    process.exit(1)
  }

  function protectStaticFiles (Request, Response, next) {
    let FilePath = Request.url                     // has been normalized before

    for (let Entry in ProtectionRegistry) {
      if (ProtectionRegistry[Entry].PathPattern.test(FilePath)) {
        authenticateUser(Request, Response, (Request, Response) => {
          let authenticatedUser = Request.authenticatedUser
          let permittedUsers    = ProtectionRegistry[Entry].permittedUsers
          switch (true) {
            case (permittedUsers == null):
            case (permittedUsers.indexOf(authenticatedUser) >= 0):
              return next()
            default:
              Response.set('WWW-Authenticate','Basic realm="' + Request.virtualHost + '"')
              return Response.sendStatus(401)
          }
        })
        return
      }
    }

    return next()                          // path does not seem to be protected
  }

//------------------------------------------------------------------------------
//--                           static File Serving                            --
//------------------------------------------------------------------------------

  const sendStaticFile = require('serve-static')(
    FileRoot, {
      index: ['index.html'],
      setHeaders: function (Response, Path /* FileStat */) {
        if (Path.endsWith('/manifest.json') || Path.endsWith('.manifest')) {
          Response.set('Content-Type', 'text/cache-manifest')
        }
      }
    }
  )

//------------------------------------------------------------------------------
//--                                 Logging                                  --
//------------------------------------------------------------------------------

  const morgan = require('morgan')

//------------------------------------------------------------------------------
//--                 common Server and Service Configuration                  --
//------------------------------------------------------------------------------

  function configure (actualServer,actualService) {
    actualService.use(configuredHelmet)
    actualService.use(PathNormalizer)     // validates paths, maps virtual hosts
    actualService.use(cors(validateCORS))//before(!) processing any entry points

  /**** Logging ****/

    actualService.use(morgan(LogFormat, {
      stream:fs.createWriteStream(
        path.join(LogRoot,(primaryDomain || 'localhost') + '.log'),
        { flags:'a' }
      )
    }))

    actualService.use(morgan(
      ':remote-addr :remote-user :method :url :status :res[content-length] - :response-time ms'
    ))

  /**** require basic authentication for Node-RED editor ****/

    actualService.use(REDSettings.httpAdminRoot, protectNodeRED)

  /**** embed Node-RED ****/

    REDSettings.userDir = path.join(ConfigRoot,REDSettings.userDir)
    REDSettings.functionGlobalContext = {
      ServerPort, RedirectionPort, behindProxy,
      primaryDomain, virtualHosts, allowSubdomains, PBKDF2Iterations,
      FileRoot, ConfigRoot, LogRoot,
      CORSRegistry, UserRegistry, ProtectionRegistry,
      functionExternalModules:true
    }

console.log('Node-RED Settings:',REDSettings)

    RED.init(actualServer,REDSettings)

    actualService.use(REDSettings.httpNodeRoot, RED.httpNode)   // for "HTTP in"
    actualService.use(REDSettings.httpAdminRoot,RED.httpAdmin) // for the Editor

  /**** require basic authentication for protected static files ****/

    actualService.get('*', protectStaticFiles)

  /**** paths not caught by Node-RED could be static files ****/

    actualService.get('*',sendStaticFile)

  /**** the following middleware should never be invoked - but who knows? ****/

    actualService.all('*', (Request, Response) => {
      Response.sendStatus(404)
    })
  }

//------------------------------------------------------------------------------
//--                              actual Server                               --
//------------------------------------------------------------------------------

  console.clear()

    const KeyFilePath = path.join(CERTFolder,'privkey.pem')
    if (! fs.existsSync(KeyFilePath)) {
      console.error('no key file at "' + KeyFilePath + '"')
      process.exit(1)
    }

    const CERTFilePath = path.join(CERTFolder,'fullchain.pem')
    if (! fs.existsSync(CERTFilePath)) {
      console.error('no cert file at "' + CERTFilePath + '"')
      process.exit(1)
    }

    const safeService = express()
    const safeServer  = https.createServer({
      key:  fs.readFileSync(KeyFilePath),
      cert: fs.readFileSync(CERTFilePath)
    }, safeService)

    if (behindProxy) { safeService.set('trust proxy',behindProxy) }

    configure(safeServer,safeService)

    let ServerInstance = safeServer.listen(ServerPort, function () {
      let ServerAddress = ServerInstance.address()
      console.log('HTTPS Server:')
      console.log('- listening at ' + ServerAddress.address + ':' + ServerAddress.port)
      console.log('- serving from ' + FileRoot + ')')
    })

    let RedirectionService
    if (RedirectionPort != null) {
      RedirectionService = express()
        if (behindProxy) { safeService.set('trust proxy',behindProxy) }

        RedirectionService.all('*',function Redirector (Request, Response) {
          let virtualHost = Request.headers[':authority'] || Request.headers.host
          if (behindProxy && (Request.headers['x-forwarded-host'] != null)) {
            virtualHost = Request.headers['x-forwarded-host']
          }

          if (virtualHost == null) {
            Response.sendStatus(404)
          } else {
            virtualHost = virtualHost.replace(/:\d+$/,'')
            Response.redirect('https://' + virtualHost + ':' + ServerPort + Request.url)
          }
        })
      let RedirectionInstance = RedirectionService.listen(RedirectionPort, function () {
        let ServerAddress = RedirectionInstance.address()
        console.log('HTTP Redirection Server:')
        console.log('- listening at ' + ServerAddress.address + ':' + ServerAddress.port)
        console.log('- serving from ' + FileRoot + ')')
      })
    }

  RED.start()

