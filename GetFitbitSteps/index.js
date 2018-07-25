const jwksRsa = require('jwks-rsa');
const request = require('request');
// Create decorator that checks the JWT signature and specified fields
const jwtValidateDecorator = require('./../auth0-func')({
  clientId: process.env.AUTH0_API_ID,
  clientSecret: jwksRsa.expressJwtSecret({
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 5,
    jwksUri: `https://${process.env.AUTH0_DOMAIN}/.well-known/jwks.json`
  }),
  algorithms: ['RS256'],
  domain: `${process.env.AUTH0_DOMAIN_URL}/`
});

// The main Functions Function
module.exports = jwtValidateDecorator((context, req) => {
  context.log('Starting.................');
  if (req.user) {
    // Get a token to access the admin API

    getAdminAccessToken()
      .then(({ object: { access_token } }) => {
        const userId = req.user.sub; // has been added to the req by the decorator
        return getUserProfile(access_token, userId);
      })
      // Get the album list from google
      .then(({ object }) => {
        const fitbit_access_token = object.identities[0].access_token; // hidden from the Auth0 console
        return getSteps(fitbit_access_token);
      })
      // Get the album titles
      .then(data => {
        context.log(data.object.summary);
        return {
          body: data.object.summary.steps
        };
      })
      .catch(err => {
        return {
          status: 400,
          body: err.message
        };
      })
      .then(res => {
        context.done(null, res);
      });
  } else {
    const res = {
      status: 400,
      body: 'Something is wrong with the Authorization token'
    };
    context.done(null, res);
  }
});

// Call a remote HTTP endpoint and return a JSON object
function requestObject(options) {
  return new Promise((resolve, reject) => {
    request(options, function(error, response, body) {
      if (error) {
        reject(error);
      } else if (200 > response.statusCode || 299 < response.statusCode) {
        reject(
          new Error(
            `Remote resource ${options.url} returned status code: ${
              response.statusCode
            }: ${body}`
          )
        );
      } else {
        const object = typeof body === 'string' ? JSON.parse(body) : body; // FIXME throws
        resolve({ code: response.statusCode, object });
      }
    });
  });
}

// Get an access token for the Auth0 Admin API
function getAdminAccessToken() {
  const options = {
    method: 'POST',
    url: `${process.env.AUTH0_DOMAIN_URL}/oauth/token`,
    headers: { 'content-type': 'application/json' },
    body: {
      client_id: process.env.AUTH0_ADMIN_CLIENT_ID,
      client_secret: process.env.AUTH0_ADMIN_CLIENT_SECRET,
      audience: `${process.env.AUTH0_DOMAIN_URL}/api/v2/`,
      grant_type: 'client_credentials'
    },
    json: true
  };
  return requestObject(options);
}

// Get the user's profile from the Admin API
function getUserProfile(accessToken, userID) {
  const options = {
    method: 'GET',
    url: `${process.env.AUTH0_DOMAIN_URL}/api/v2/users/${userID}`,
    headers: {
      Authorization: `Bearer ${accessToken}`
    }
  };
  return requestObject(options);
}

// Get user Google Photos album list
function getSteps(accessToken) {
  const options = {
    method: 'GET',
    url: 'https://api.fitbit.com/1/user/-/activities/date/2018-07-16.json',
    headers: {
      Authorization: `Bearer ${accessToken}`
    }
  };
  return requestObject(options);
}
