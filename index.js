/**
 * cognito test
 *
 */

const jwt = require('jsonwebtoken');
const async = require('async');
const axios = require('axios');
const jwkToPem = require('jwk-to-pem');
const AWS = require('aws-sdk');
const passport = require('passport');
const GoogleTokenStrategy = require('passport-google-id-token');

const IDENTITY_POOLID = 'ap-northeast-1:4e86b831-da7f-47d5-8382-3d800cd28a25';
const COGNITO_DATASET_NAME = 'userData';

AWS.config.region = 'ap-northeast-1';

const cognitoidentity = new AWS.CognitoIdentity();
const cognitosync = new AWS.CognitoSync();
const iss = 'https://cognito-identity.amazonaws.com';
let identityId = null;

const jwks = {
  cognito: 'https://cognito-identity.amazonaws.com/.well-known/jwks_uri',
  'accounts.google.com': 'https://accounts.google.com/.well-known/openid-configuration',
  'graph.facebook.com': '',
};

let pems;

/**
 * Records を Object に変換
 */
const parseData = (rec) => {
  const obj = {};

  rec.forEach(r => {
    obj[r.Key] = r.Value;
  });

  return obj;
};

const checkJwt = () => {
  return new Promise((resolve, reject) => {
    // Download the JWKs and save it as PEM
    axios.get(`${iss}/.well-known/jwks_uri`).then(response => {
      if (response.status === 200) {
        pems = {};

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

        console.log(pems, 'pems');
        resolve(pems);
      }
    }).catch(error => {
      console.log(error, 'error');
      reject(error);
    });
  });
};

/**
 * 認証情報がない場合はUnauthenticated Userを作成
 */
// const createUser = data => {
//   return new Promise(resolve => {
//     AWS.config.credentials = new AWS.CognitoIdentityCredentials({
//       IdentityId: identityId,
//       IdentityPoolId: IDENTITY_POOLID
//     });

//     AWS.config.credentials.get(err => {
//       if (err) {
//         resolve({ success: false });

//         return;
//       }
//       identityId = AWS.config.credentials.identityId;

//       resolve({
//         identityId: identityId
//       });
//     });
//   });
// }


/**
 * Developer Authenticated 認証
 */
const authUser = ({ accessToken, principalId, provider }) => {
  return new Promise(resolve => {
    // ここで外部認証処理...
    setTimeout(() => {
      // 結果を保持する
      const params = {
        IdentityPoolId: IDENTITY_POOLID,
        IdentityId: principalId,
        Logins: {
          [provider]: accessToken,
        }
      };

      cognitoidentity.getOpenIdTokenForDeveloperIdentity(params, (err, res) => {
        if (err) {
          resolve({ success: false });

          return;
        }

        identityId = res.IdentityId;
        resolve(res);
      });

    }, 500);
  });
};


/**
 * List store Data
 */
const listData = data => {
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

      console.log(parseData(res.Records));

      resolve(res);
    });
  });
};


/**
 * add store Data
 */
const addData = data => {
  return new Promise(resolve => {
    if (!identityId) {
      resolve({
        success: false
      });

      return;
    }

    const params = {
      DatasetName: COGNITO_DATASET_NAME,
      IdentityId: identityId,
      IdentityPoolId: IDENTITY_POOLID,
      SyncSessionToken: data.SyncSessionToken,
      RecordPatches: [{
        Key: 'USER_ID',
        Op: 'replace',
        SyncCount: data.DatasetSyncCount,
        Value: 'aaaaaaaaaaaaa'
      }],
    };

    cognitosync.updateRecords(params, (err, data) => {
      if (err) {
        resolve({ success: false });

        return;
      }

      resolve(parseData(data.Records));
    });
  });
}

const ValidateToken = (pems, event, context) => {
  const token = event.authorizationToken;

  // Fail if the token is not jwt
  const decodedJwt = jwt.decode(token, { complete: true });

  console.log(decodedJwt);

  if (!decodedJwt) {
    console.log("Not a valid JWT token");
    context.fail("Unauthorized");
    return;
  }

  // Fail if token is not from your User Pool
  if (decodedJwt.payload.iss !== iss) {
    console.log("invalid issuer");
    context.fail("Unauthorized");
    return;
  }

  //Reject the jwt if it's not an 'Access Token'
  // if (decodedJwt.payload.token_use != 'access') {
  //   console.log("Not an access token");
  //   context.fail("Unauthorized");
  //   return;
  // }

  // Get the kid from the token and retrieve corresponding PEM
  const kid = decodedJwt.header.kid;
  const pem = pems[kid];
  if (!pem) {
    console.log('Invalid access token');
    context.fail("Unauthorized");
    return;
  }

  // Verify the signature of the JWT token to ensure it's really coming from your User Pool
  jwt.verify(token, pem, { issuer: iss }, (err, payload) => {
    if (err) {
      context.fail('Unauthorized');
    } else {
      const principalId = payload.sub;
      const provider = payload.amr && payload.amr[1];
      const accessToken = event.accessToken;

      if (!principalId || !provider || !accessToken) {
        console.log('Wrong token or no access token.');
        context.fail('Wrong token or no access token.');
      }

      // Using access token to retrieve user profile and save it with identityId in aws cognito

    }
  });
};

exports.handler = function (event, context) {
  const query = event || {};

  if (!event.accessToken || !event.authorizationToken) {
    context.fail('Please input accessToken & authorizationToken completely.');
  }

  if (!pems) {
    checkJwt().then(pems => {
      ValidateToken(pems, event, context);
    }).catch(error => {
      context.fail(error);
    });
  } else {
    ValidateToken(pems, event, context);
  }



  // //認証情報ない
  // if (!query.identityId && !query.appId) {
  //   createUser().then(res => {
  //     context.succeed(res);
  //   });

  //   return;
  // }

  // // appIdがない
  // if (!query.appId) {
  //   identityId = query.identityId;
  //   createUser().then(listData)
  //     .then(addData)
  //     .then(res => {
  //       context.succeed({
  //         identityId: identityId,
  //         userdata: res
  //       });
  //     });

  //   return;
  // }

  // if (query.identityId) {
  //   identityId = query.identityId;
  // }

  // console.log('190', identityId);

  // authUser({
  //   user: query.appId
  // }).then(listData)
  //   .then(addData)
  //   .then(res => {
  //     context.succeed({
  //       identityId: identityId,
  //       userdata: res
  //     });
  //   });
};
