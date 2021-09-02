# node-red-within-express #

This repository contains an HTTP server based on [Node.js](https://nodejs.org/en/) with [Express.js](http://expressjs.com/) including an embedded [Node-RED](https://nodered.org/) instance.

Its intended purpose is to provide a very easily maintainable server for development and test of web and REST service prototypes.

## Features ##

The implemented server has the following features:

* **HTTPS with optional HTTP-to-HTTPS Redirection**<br>the main server handles HTTPS only as it is becoming increasingly difficult to deliver pure HTTP content to browsers (even locally). If desired, an additional auxiliary HTTP server may be started which redirects incoming requests to its HTTPS counterpart
* **Proxy Support**
* **Support for "self-signed" or "Let's Encrypt" Certificates**<br>for local tests, it may be sufficient to generate self-signed certificates (instructions can be found below). For public tests, the server also supports certificates generated by ["Let's Encrypt"](https://letsencrypt.org/)
* **Support for "virtual Hosts" and Subdomains**<br>the server may optionally support "virtual hosts" and serve multiple domains (including subdomains) simultaneously. In this case, each domain will be mapped to an individual subtree on the file system in order to isolate the domains from each other
* **"www" Subdomains**<br>if desired, "www" subdomains can be mapped to their original domain (since they usually serve the same content anyway)
* **embedded Node-RED runtime**<br>incoming requests will first be compared to the entry points given by "HTTP in" nodes - and their flows be executed whenever the URL paths match (if "virtual hosts" are to be respected, all these entry points become domain-specific and their paths must therefore be prefixed by the domain they belong to). Requests not matching any "HTTP in" node entry points will then be used to serve static files from the file system (or generate a 404 response if no matching file could be found)
* **embedded Node-RED editor**<br>the embedded Node-RED editor is generally protected by "basic HTTP authentication": for that purpose, the server always comes with a "User Registry" which already contains a single user (named "node-red" with the initial password "t0pS3cr3t!") who is allowed to access the Node-RED editor
* **User Registry with PBKDF2 hashed Passwords and Role Support**<br>the list of registered users is stored in a JSON file with passwords saved as PBKDF2 hashes with random salt. While the server itself does not contain any user management, such a feature may easily be added as a Node-RED flow - although, in fact, a simple text editor is already sufficient to add new users, change existing ones or remove obsolete users
* **Path-specific CORS**<br>"Cross-Origin Resource Sharing" may be configured for complete sites as a whole or for specific resource paths with any desired granularity
* **configurable "Content Security Policies"**<br>the server is secured using [Helmet](https://github.com/helmetjs/helmet) with a configuration option for specific "Content Security Policies"
* **standard-compliant Logging**<br>access logging is done using [morgan](https://expressjs.com/en/resources/middleware/morgan.html). Logs may be written into a file either in "standard Apache common log format" or any other format

## Installation and Use ##

You may easily install and run this server on your machine.

Just install [NPM](https://docs.npmjs.com/) according to the instructions for your platform and follow these steps:

1. either clone this repository using [git](https://git-scm.com/) or [download a ZIP archive](https://github.com/rozek/node-red-within-express/archive/refs/heads/main.zip) with its contents to your disk and unpack it there 
2. open a shell and navigate to the root directory of this repository
3. run `npm install` in order to install the server

### Preparing the first Start ###

For a quick start, the server comes preconfigured for two different use cases:

* *without* virtual hosts processing<br>this variant does not require much preparation and is ideal for initial experiments
* *with* virtual hosts processing<br>this variant requires a bit of preparational work but may be used to test installations serving multiple domains

#### Variant without virtual Hosts Processing ####

#### Variant with virtual Hosts Processing ####

### First Experiments ###

## Invocation Parameters ##

The server in this repo has been implemented as a Node.js script and can be invoked as follows

```
node WebServer.js [options] <file-root> [<configuration-folder> [<log-folder>]]
```

with the following arguments:

* **`<file-root>`**<br>specifies the root folder (relative to the server's current working directory) of all deliverable static files. By default, this is a subfolder of the current working directory called `public`
* **`<configuration-folder>`**<br>specifies the folder (relative to the server's current working directory) where configuration files (such as the list of registered users) are found. By default, this is the current working directory itself
* **`<log-folder>`**<br>specifies the folder (relative to the server's current working directory) into which the log file is written. By default, this is a subfolder of the current working directory called `logs`

The following options are supported:

* **`--server-port <port>`**<br>specifies the TCP port at which to listen for incoming HTTPS requests. The default is `8443`
* **`--redirection-port <port>`**<br>if provided, this option activates HTTP-to-HTTPS redirection and specifies the TCP port at which to listen for incoming HTTP requests
* **`--proxy <proxy>`**<br>activates and configures proxy support. Consider the [Express.js documentation](https://expressjs.com/en/guide/behind-proxies.html) for a list and explanation of actually allowed values
* **`--domain <domain>`**<br>specifies the primary domain of this server. It should be the "common name" (CN) of the associated server certificate and also appears in the log file name. If virtual hosts are given as well (even if the list is empty), the primary domain is automatically added to that list
* **`--virtual-hosts <virtual-hosts>`**<br>activates virtual hosts processing and configures the domains to handle. The given argument may either be an empty string (`""`) or a string containing a comma-separated list of internet domains. All mentioned domains should also be specified as "subject alternative names" (SAN) in the server certificate
* **`--allow-subdomains`**<br>if specified, all subdomains of the given primary domain and virtual hosts are processed as well. In this case, the server certificate should also contain "subject alternative names" (SAN) with wildcards of the form `*.<domain>`
* **`--ignore-www`**<br>if specified, subdomains of the form `www.<domain>` are not treated as a separate subdomain but mapped to their main `<domain>`
* **`--cert-folder <folder>`**<br>specifies the folder where to find server certificates. By default, this is a subfolder of the server's current working directory called `certificates`
* **`--pbkdf2-iterations <count>`**<br>specifies the number of iterations when computing PBKDF2 hashes. Default is 100000
* **`--log-format <format>`**<br>specifies the format in which log entries are written into a file. Consider the [morgan documentation]() for a list and explanation of permitted settings. Default is `common`


### Configuring Domains and Virtual Hosts ###

## Embedded Node-RED Instance ##

## User registry ##

### Generating "Salt" and "Hash" ###

## CORS Support ##

## Content Security Policies ##

## Logging ##



* HTTPS (and auto-redirection from HTTP to HTTPS) with self-signed or "Let's Encrypt" Certificates
* virtual Hosts
  * how to configure Domains in /etc/hosts
  * Subdomains
* User Registry
  * Basic Auth and PBKDF2
  * adding Users to the Registry
  * protecting the Node-RED Editor
* CORS Support
* initial Node-RED Flows
* Postman Collection for Tests


## License ##

[MIT License](LICENSE.md)
