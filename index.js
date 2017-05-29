const jwt = require('jsonwebtoken');
const axios = require('axios');
const jwkToPem = require('jwk-to-pem');
const AWS = require('aws-sdk');

const IDENTITY_POOLID = 'ap-northeast-1:4e86b831-da7f-47d5-8382-3d800cd28a25';
const COGNITO_DATASET_NAME = 'userData';

AWS.config.region = 'ap-northeast-1';

const cognitoidentity = new AWS.CognitoIdentity();
const cognitosync = new AWS.CognitoSync();

/**
 * Convert object to dataset format
 */
const parseData = (rec) => {
  const obj = {};

  rec.forEach(r => {
    obj[r.Key] = r.Value;
  });

  return obj;
};

/**
 * Download JWT key
 */
const downloadKey = () => {
  return new Promise((resolve, reject) => {
    const url = 'https://cognito-identity.amazonaws.com/.well-known/jwks_uri';
    // Download the JWKs and save it as PEM
    axios.get(url).then(response => {
      if (response.status === 200) {
        const pems = {};

        const keys = response.data.keys;

        for (let i = 0; i < keys.length; i++) {
          // Convert each key to PEM
          const key_id = keys[i].kid;
          const modulus = keys[i].n;
          const exponent = keys[i].e;
          const key_type = keys[i].kty;
          const jwk = {
            kty: key_type,
            n: modulus,
            e: exponent,
          };
          const pem = jwkToPem(jwk);

          pems[key_id] = pem;
        }

        resolve(pems);
      }
    }).catch(error => {
      console.log(error, 'error');
      reject(error);
    });
  });
};

/**
 * List store Data
 */
const listData = ({ identityId, profile }) => {
  return new Promise(resolve => {
    if (!identityId) {
      resolve({
        success: false
      });

      return;
    }

    cognitosync.listRecords({
      DatasetName: COGNITO_DATASET_NAME,
      IdentityId: identityId,
      IdentityPoolId: IDENTITY_POOLID
    }, (err, res) => {
      if (err) {
        console.log('err', err);
        resolve({ success: false });

        return;
      }

      console.log('res', res);
      console.log('parsedData', parseData(res.Records));

      resolve({ data: res, identityId, profile });
    });
  });
};

/**
 * add store data
 */
const addData = ({ data, identityId, profile }) => {
  return new Promise(resolve => {
    if (!identityId) {
      resolve({
        success: false,
      });

      return;
    }

    const params = {
      DatasetName: COGNITO_DATASET_NAME,
      IdentityId: identityId,
      IdentityPoolId: IDENTITY_POOLID,
      SyncSessionToken: data.SyncSessionToken,
      RecordPatches: [{
        Key: 'facebookId',
        Op: 'replace',
        SyncCount: data.DatasetSyncCount,
        Value: profile.id,
      }, {
        Key: 'name',
        Op: 'replace',
        SyncCount: data.DatasetSyncCount,
        Value: profile.name,
      }, {
        Key: 'gender',
        Op: 'replace',
        SyncCount: data.DatasetSyncCount,
        Value: profile.gender,
      }, {
        Key: 'email',
        Op: 'replace',
        SyncCount: data.DatasetSyncCount,
        Value: profile.email,
      }, {
        Key: 'birthday',
        Op: 'replace',
        SyncCount: data.DatasetSyncCount,
        Value: profile.birthday,
      }],
    };

    cognitosync.updateRecords(params, (err, data) => {
      if (err) {
        resolve({ success: false });

        return;
      }

      resolve({
        userData: parseData(data.Records),
        success: true,
        identityId,
      });
    });
  });
}

/**
 * Validate token
 */
const validateToken = (pems, event, context) => {
  return new Promise((resolve, reject) => {
    const iss = 'https://cognito-identity.amazonaws.com';
    const token = JSON.parse(event.body).openIdToken;

    // Fail if the token is not jwt
    const decodedJwt = jwt.decode(token, { complete: true });

    console.log(decodedJwt, 'jwt');

    if (!decodedJwt) {
      reject('Not a valid JWT token');

      return;
    }

    // Fail if token is not from your User Pool
    if (decodedJwt.payload.iss !== iss) {
      reject('invalid issuer');

      return;
    }

    // Get the kid from the token and retrieve corresponding PEM
    const kid = decodedJwt.header.kid;
    const pem = pems[kid];

    if (!pem) {
      reject('Invalid access token');

      return;
    }

    // Verify the signature of the JWT token to ensure it's really coming from your User Pool
    jwt.verify(token, pem, { issuer: iss }, (err, payload) => {
      if (err) {
        reject('Unauthorized');

        return;
      } else {
        const principalId = payload.sub;
        const provider = payload.amr && payload.amr[1];
        const accessToken = JSON.parse(event.body).accessToken;

        console.log(payload, 'payload');
        console.log(accessToken, 'accessToken');

        if (!principalId || !provider || !accessToken) {
          reject('Wrong token or no access token.');
        } else {
          // Using access token to retrieve user profile and save it with identityId in aws cognito
          resolve({ principalId, provider, accessToken });
        }

        return;
      }
    });
  });
};

/**
 * Retrieve SNS user profile
 */
const retrieveProfile = (provider, accessToken) => {
  console.log(provider, accessToken);

  return new Promise((resolve, reject) => {
    if (provider === 'accounts.google.com') {
      axios.get(`https://www.googleapis.com/oauth2/v3/tokeninfo?id_token=${accessToken}`)
        .then(response => {
          if (response.status === 200) {
            const profile = response.data;

            resolve({
              name: profile.name,
              email: profile.email,
            });
          } else {
            reject(response.status);
          }
        })
        .catch(error => {
          reject(`Retrieve google user data failed! ${error}`);
        });
    } else if (provider === 'graph.facebook.com') {
      axios.get(`https://graph.facebook.com/v2.9/me?fields=id%2Cname%2Cbirthday%2Cgender&access_token=${accessToken}`)
        .then(response => {
          if (response.status === 200) {
            const profile = response.data;

            resolve({
              name: profile.name,
              facebookId: profile.id,
              birthday: profile.birthday,
              gender: profile.gender,
              email: profile.email,
            });
          } else {
            reject(response.status);
          }
        })
        .catch(error => {
          reject('error');
        });
    } else {
      reject('Unknown provider');
    }
  });
};

exports.handler = (event, context) => {
  const query = event || {};
  const bodyData = JSON.parse(event.body);

  if (!bodyData.accessToken || !bodyData.openIdToken) {
    const result = {
      statusCode: 500,
      headers: {},
      body: JSON.stringify({ error: 'Please input accessToken & openIdToken completely.' }),
    };

    context.fail(result);
  }

  // Download Cognito's JWT first
  downloadKey().then(pems => {
    // Validate token
    validateToken(pems, event, context)
      .then(response => {
        const provider = response.provider;
        const accessToken = response.accessToken;
        const principalId = response.principalId;

        console.log(response, 'response');

        retrieveProfile(provider, accessToken)
          .then(profile => {
            console.log(profile);

            listData({
              identityId: principalId,
              profile,
            })
            .then(addData)
            .then(res => {
              const result = {
                statusCode: 200,
                headers: {},
                body: JSON.stringify(res),
              };

              context.succeed(result);
            });
          })
          .catch(error => {
            console.log('retrieve profile error', error);

            const result = {
              statusCode: 500,
              headers: {},
              body: JSON.stringify({ error }),
            };

            context.fail(result);
          });
      })
      .catch(error => {
        console.log('validate token error', error);

        const result = {
          statusCode: 401,
          headers: {},
          body: JSON.stringify({ error }),
        };

        context.fail(result);
      });
  }).catch(error => {
    console.log('download key error', error);

    const result = {
      statusCode: 500,
      headers: {},
      body: JSON.stringify({ error }),
    };

    context.fail(result);
  });
};
