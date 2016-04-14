var debug = require('debug');
var error = debug('express-hod-sso-middleware:error');
var log = debug('express-hod-sso-middleware:log');

log.log = console.log.bind(console);

module.exports = {
    error: error,
    log: log
};
