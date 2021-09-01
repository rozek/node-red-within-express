#!/usr/bin/env node
  const crypto = require('crypto')

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

  const Arguments = require('commander')
  Arguments
    .usage('[options]')
    .option('--pbkdf2-iterations <count>', 'PBKDF2 iteration count', parsePBKDF2Iterations)

  const PBKDF2Iterations = Arguments.opts().pbkdf2Iterations || 100000

  const stdin  = process.stdin
  const stdout = process.stdout

  function readPassword (Prompt, CallBack) {
    if (Prompt != null) {
      stdout.write(Prompt)
    }

    stdin.resume()
    stdin.setRawMode(true)
    stdin.resume()
    stdin.setEncoding('utf8')

    let Password = ''
    stdin.on('data', function (readChar) {
      readChar = readChar.toString('utf8')
      switch (readChar) {
        case '\n':
        case '\r':
        case '\u0004':
          stdout.write('\n')
          stdin.setRawMode(false)
          stdin.pause()
          return CallBack(null,Password)
        case '\u0003': // ctrl-c
          return CallBack(new Error('aborted'))
        case '\u007f': // backspace
          Password = Password.slice(0, Password.length-1)
          stdout.clearLine()
          stdout.cursorTo(0)
            if (Prompt != null) { stdout.write(Prompt) }
          stdout.write(Password.split('').map(() => '*').join(''))
          break
        default:
          stdout.write('*')
          Password += readChar
      }
    })
  }

  readPassword('enter your password: ', (Error,Password) => {
    if (Error == null) {
      let PasswordSalt = crypto.randomBytes(16)
      let PasswordHash = crypto.pbkdf2Sync(
        Password, PasswordSalt, PBKDF2Iterations, 64, 'sha512'
      )

      stdout.write('"Salt":"' + PasswordSalt.toString('hex') + '"\n')
      stdout.write('"Hash":"' + PasswordHash.toString('hex') + '"\n')
    } else {
      if (Error.message === 'aborted') {
        stdout.write('\n')
        process.exit()
      } else {
        throw Error
      }
    }
  })
