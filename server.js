var url     = require('url'),
    http    = require('http'),
    https   = require('https'),
    fs      = require('fs'),
    qs      = require('querystring'),
    express = require('express'),
    moesif  = require('moesif-nodejs'),
    app     = express();

var TRUNCATE_THRESHOLD = 10,
    REVEALED_CHARS = 3,
    REPLACEMENT = '***';

// Use Moesif middleware to log incoming API calls.  
const moesifMiddleware = moesif({
  applicationId: process.env.MOESIF_APPLICATION_ID
});
app.use(moesifMiddleware);

// Load config defaults from JSON file.
// Environment variables override defaults.
function loadConfig() {
  var config = JSON.parse(fs.readFileSync(__dirname+ '/config.json', 'utf-8'));
  log('Configuration');
  for (var i in config) {
    config[i] = process.env[i.toUpperCase()] || config[i];
    if (i === 'oauth_client_id' || i === 'oauth_client_secret') {
      log(i + ':', config[i], true);
    } else {
      log(i + ':', config[i]);
    }
  }
  return config;
}

var config = loadConfig();

function authenticate(code, client_id, cb) {
  const client_ids = config.oauth_client_id.split(',');
  const index_of_client = client_ids.indexOf(client_id);
  if (index_of_client === -1) {
    cb('Unauthorized');
    return;
  }

  const client_secret = config.oauth_client_secret.split(',')[index_of_client];

  var data = qs.stringify({
    client_id: client_id,
    client_secret: client_secret,
    code: code
  });

  var reqOptions = {
    host: config.oauth_host,
    port: config.oauth_port,
    path: config.oauth_path,
    method: config.oauth_method,
    headers: { 'content-length': data.length }
  };

  var body = "";
  var req = https.request(reqOptions, function(res) {
    res.setEncoding('utf8');
    res.on('data', function (chunk) { body += chunk; });
    res.on('end', function() {
      cb(null, qs.parse(body).access_token);
    });
  });

  req.write(data);
  req.end();
  req.on('error', function(e) { cb(e.message); });
}

/**
 * Handles logging to the console.
 * Logged values can be sanitized before they are logged
 *
 * @param {string} label - label for the log message
 * @param {Object||string} value - the actual log message, can be a string or a plain object
 * @param {boolean} sanitized - should the value be sanitized before logging?
 */
function log(label, value, sanitized) {
  value = value || '';
  if (sanitized){
    if (typeof(value) === 'string' && value.length > TRUNCATE_THRESHOLD){
      console.log(label, value.substring(REVEALED_CHARS, 0) + REPLACEMENT);
    } else {
      console.log(label, REPLACEMENT);
    }
  } else {
    console.log(label, value);
  }
}

// Convenience for allowing CORS on routes - GET only
app.all('*', function (req, res, next) {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type');
  next();
});

function respond_to_authentication(res, err, token) {
  var result
  if (err || !token) {
    result = {"error": err || "bad_code"};
    log(result.error);
  } else {
    result = {"token": token};
    log("token", result.token, true);
  }
  res.json(result);
}

app.get('/authenticate/:code/client_id/:client_id', function(req, res) {
  log('authenticating code:', req.params.code, true);
  authenticate(req.params.code, req.params.client_id, (err, token) => respond_to_authentication(res, err, token));
});

app.get('/authenticate/:code', function(req, res) {
  const client_id = config.oauth_client_id.split(',')[0];
  log('authenticating code:', req.params.code, true);
  authenticate(req.params.code, client_id, (err, token) => respond_to_authentication(res, err, token));
});

var port = process.env.PORT || config.port || 9999;

app.listen(port, null, function (err) {
  log('Gatekeeper, at your service: http://localhost:' + port);
});
