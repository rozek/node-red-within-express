# node-red-within-express #

This repository contains an HTTP server based on [Node.js](https://nodejs.org/en/) with [Express.js](http://expressjs.com/) with an embedded [Node-RED](https://nodered.org/) instance.

Its intended purpose is to provide a very easily maintainable server for development and test of web and REST service prototypes.





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

