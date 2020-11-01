# passport-facebook-token usage note

Once our server is up:

```js
const FacebookTokenStrategy = require('passport-facebook-token');

passport.use(new FacebookTokenStrategy({
    clientID: FACEBOOK_APP_ID,
    clientSecret: FACEBOOK_APP_SECRET,
    fbGraphVersion: 'v3.0'
  }, function(accessToken, refreshToken, profile, done) {
    User.findOrCreate({facebookId: profile.id}, function (error, user) {
      return done(error, user);
    });
  }
));
```
We immediately configure our authentication strategy by newing the `FacebookTokenStrategy`, let's look into class definition of `FacebookTokenStrategy`:

https://github.com/drudge/passport-facebook-token/blob/716461bea0153582e8de2a77a2e36d6f030557c5/src/index.js#L26-L38

```js
module.exports = class FacebookTokenStrategy extends OAuth2Strategy {
  constructor (_options, _verify) {
    const options = _options || {};
    const verify = _verify;
    const _fbGraphVersion = options.fbGraphVersion || 'v2.6';

    options.authorizationURL = options.authorizationURL || `https://www.facebook.com/${_fbGraphVersion}/dialog/oauth`;
    options.tokenURL = options.tokenURL || `https://graph.facebook.com/${_fbGraphVersion}/oauth/access_token`;

    super(options, verify);

    this.name = 'facebook-token';
    this._accessTokenField = options.accessTokenField || 'access_token';
    
    ...
```
The constructor of FacebookTokenStrategy would be executed, and it also triggers `OAuth2Strategy`, which is its parent class, by `super(options, verify)`, **an important thing I want to mention here is**,

```js
    options.authorizationURL = options.authorizationURL || `https://www.facebook.com/${_fbGraphVersion}/dialog/oauth`;
    options.tokenURL = options.tokenURL || `https://graph.facebook.com/${_fbGraphVersion}/oauth/access_token`;
    super(options, verify);
```
The declarations of `options.authorizationURL` and `options.tokenURL` are not used even they are passed to `OAuth2Strategy`. `https://www.facebook.com/${_fbGraphVersion}/dialog/oauth` and `https://graph.facebook.com/${_fbGraphVersion}/oauth/access_token` are mentioned in https://developers.facebook.com/docs/facebook-login/manually-build-a-login-flow.

It once made me think this module really goes through the flow from Step A to Step D again, which it's already been done on frontend when user log in by Facebook Login JavaScript SDK, because the callback of `FacebookTokenStrategy` returns an `accessToken`.

```
     +--------+                               +---------------+
     |        |--(A)- Authorization Request ->|   Resource    |
     |        |                               |     Owner     |
     |        |<-(B)-- Authorization Grant ---|               |
     |        |                               +---------------+
     |        |
     |        |                               +---------------+
     |        |--(C)-- Authorization Grant -->| Authorization |
     | Client |                               |     Server    |
     |        |<-(D)----- Access Token -------|               |
     |        |                               +---------------+
     |        |
     |        |                               +---------------+
     |        |--(E)----- Access Token ------>|    Resource   |
     |        |                               |     Server    |
     |        |<-(F)--- Protected Resource ---|               |
     +--------+                               +---------------+

                     Figure 1: Abstract Protocol Flow
```

**I'll show you that this `accessToken` is still the one we get from frontend and give it to passport's `authenticate` function**.

```js
app.post(
  '/api/auth/facebook/token',
  passport.authenticate('facebook-token'),
  function (req, res) { ... },
)
```

A small sum up here is, acutally the mechanism of this module to verify the user is mainly with

https://github.com/drudge/passport-facebook-token/blob/716461bea0153582e8de2a77a2e36d6f030557c5/src/index.js#L98-L105

```js
userProfile (accessToken, done) {
  let profileURL = new URL(this._profileURL);


  // For further details, refer to https://developers.facebook.com/docs/reference/api/securing-graph-api/
  if (this._enableProof) {
    const proof = crypto.createHmac('sha256', this._clientSecret).update(accessToken).digest('hex');
    profileURL.search = `${profileURL.search ? profileURL.search + '&' : ''}appsecret_proof=${encodeURIComponent(proof)}`;
  }
```
**This module doesn't re-ask another `accessToken`, it just uses the one we give and the app secret that only our backend knows to make a request to fetch user's profile, so if any one of `accessToken` or `appSecret` is wrong, we won't get the user profile.**

> :warning: The test to do: in https://developers.facebook.com/docs/reference/api/securing-graph-api/ which is mentioned in the comment in the `userProfile` above, it says we have to turn on `Requre App Secret`. In development mode now, I haven't turned on that and there has been no problem yet. But it should be turned on or our practice of authentication would be just meaningless?

Brief notes here:
1. The OAuth2Strategy.prototype.authenticate in `OAuth2Strategy` is never executed when we are using `FacebookTokenStrategy`, it has its own `authenticate` funtion, we are using this one.

2. `this._loadUserProfile` in `authenticate` of `FacebookTokenStrategy` is inherited from `OAuth2Strategy`, but if you look into it, it ends up using the `userProfile` defined in `FacebookTokenStrategy`.

```
facebook-src-token/src/index.js                                   passport-oauth2/lib/strategy.js                                   oauth/lib/oauth2.js

                                                                                                                                Configuration phase 
----------------------------------------------------------------------------------------------------------------------------------------------------------
FacebookTokenStrategy                                          OAuth2Strategy                                                  OAuth2
constructor() {
  ...
  super();          -------------------------->             ...
                                                            ...
                                                            ...
                                                            this._oauth2 = new OAuth2(...); -------------------------->   exports.OAuth2 = 
                                                                                                                          function(
                                                                                                                            clientId,
                                                                                                                            clientSecret,
                                                                                                                            baseSite,
                                                                                                                            authorizePath,
                                                                                                                            accessTokenPath,
                                                                                                                            customHeaders
                                                                                                                           ) {
                                                                                                                            this._clientId= clientId;
                                                                                                                            this._clientSecret= clientSecret;
                                                                                                                            this._baseSite= baseSite;
                                                                                                                            this._authorizeUrl= authorizePath
                                                                                                                              || "/oauth/authorize";
                                                                                                                            this._accessTokenUrl= accessTokenPath
                                                                                                                              || "/oauth/access_token";
                                                                                                                            this._accessTokenName= "access_token";
                                                                                                                            this._authMethod= "Bearer";
                                                                                                                            this._customHeaders = customHeaders
                                                                                                                              || {};
                                                                                                                            ...
                                                                                                                          };
                                                                                                                          // It doens't make any request
  ...
}
----------------------------------------------------------------------------------------------------------------------------------------------------------
facebook-src-token/src/index.js                                   passport-oauth2/lib/strategy.js                                   oauth/lib/oauth2.js

                                                                                                        When passport.authenticate('facebook-token') happens

----------------------------------------------------------------------------------------------------------------------------------------------------------
FacebookTokenStrategy                                          OAuth2Strategy                                                  OAuth2

authenticate() {
  const accessToken =
   this.lookup(req, this._accessTokenField);    (inherited)
   this._loadUserProfile(accessToken, ()=>{});  ---------->     OAuth2Strategy.prototype._loadUserProfile() {
}                                                                 var self = this;
                                                                  function () {
                                                                    ...
userProfile (accessToken, done) {               <----------         return self.userProfile(accessToken, done);
  const proof =                                                     // self ----> FacebookTokenStrategy
    crypto.createHmac(                                            }                                          
      'sha256',                                                 }
       this._clientSecret
    ).update(accessToken).digest('hex');
  
  profileURL.search =
    `${profileURL.search ?
      profileURL.search + '&'
        :
      ''}appsecret_proof=${encodeURIComponent(proof)}`;

  profileURL.search =
    `${profileURL.search ?
      profileURL.search + '&'
        :
      ''}fields=${fields}`;
                                                                             (definition)
  this._oauth2.get(profileURL, accessToken, () => {     ------------------------------------------------------------->   this._request(
    // a request to facebook to fetch                                                                                       "GET",
    // user profile just happened.                                                                                          url,
                                                                                                                            headers,
                                                                                                                            "",
                                                                                                                            access_token,
                                                                                                                            callback,   
                                                                                                                         ) {};

    // The rest of this callback handles
    // the profile data and call the
    // `done` which is the callback from
    //  our app.
  });
}

The url to this request is ‘/v8.0/me?appsecret_proof=xxxx&fields=id,name,last_name,first_name,middle_name,email&access_token=xxxxx’
which is actually a graph api with appsecret
```
