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

