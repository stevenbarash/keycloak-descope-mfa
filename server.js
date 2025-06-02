require('dotenv').config();
const express = require('express');
const passport = require('passport');
const OIDCStrategy = require('passport-openidconnect').Strategy;
const session = require('express-session');
const path = require('path');
const axios = require('axios');

const app = express();

// Session setup
app.use(session({ secret: 'test', resave: false, saveUninitialized: true }));

// Passport setup
passport.use('oidc', new OIDCStrategy({
  issuer: process.env.OIDC_ISSUER,
  authorizationURL: `${process.env.OIDC_ISSUER}/protocol/openid-connect/auth`,
  tokenURL: `${process.env.OIDC_ISSUER}/protocol/openid-connect/token`,
  userInfoURL: `${process.env.OIDC_ISSUER}/protocol/openid-connect/userinfo`,
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL: process.env.CALLBACK_URL,
  scope: 'openid profile email'
}, (issuer, sub, profile, accessToken, refreshToken, params, done) => {
  // Patch: ensure email and id are present
  if (!profile.email && profile.emails && profile.emails.length > 0) {
    profile.email = profile.emails[0].value;
  }
  if (!profile.id) {
    profile.id = sub;
  }
  console.log('OIDC profile:', profile);
  profile._keycloak = {
    accessToken,
    refreshToken,
    idToken: params.id_token
  };
  return done(null, profile);
}));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

app.use(passport.initialize());
app.use(passport.session());

// Serve static files (for custom CSS/images if needed)
app.use(express.static(path.join(__dirname, 'public')));

// Helper: Render HTML with Bootstrap
function renderPage({ title, body, user }) {
  return `<!DOCTYPE html>
  <html lang="en">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${title}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>body { background: #f8f9fa; } .container { margin-top: 60px; }</style>
  </head>
  <body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
      <div class="container-fluid">
        <a class="navbar-brand" href="/">Keycloak OIDC Demo</a>
        <div class="d-flex">
          ${user ? `<span class="navbar-text me-3">Hello, ${user.displayName || user.id}</span><a href="/logout" class="btn btn-outline-light">Logout</a>` : `<a href="/login" class="btn btn-light">Login</a>`}
        </div>
      </div>
    </nav>
    <div class="container">
      ${body}
    </div>
  </body>
  </html>`;
}

// Routes
app.get('/', (req, res) => {
  if (req.isAuthenticated()) {
    res.send(renderPage({
      title: 'Welcome',
      user: req.user,
      body: `
        <div class="card shadow-sm p-4 mb-4">
          <h2 class="mb-3">Welcome, ${req.user.displayName || req.user.id}!</h2>
          <p class="lead">You are logged in via <strong>Keycloak</strong>.</p>
          <h5 class="mt-4">Your Authentication Details</h5>
          <pre class="bg-light p-3 rounded border">${JSON.stringify(req.user, null, 2)}</pre>
          <a href="/logout" class="btn btn-danger mt-3">Logout</a>
        </div>
        <div class="card shadow-sm p-4">
          <h4>How it Works</h4>
          <ol class="mb-2">
            <li><strong>Login with Keycloak:</strong> Authenticate using your Keycloak credentials.</li>
            <li><strong>Access Granted:</strong> Upon successful authentication, you are logged in and can view your profile details above.</li>
          </ol>
          <p class="text-muted">This demo showcases a seamless integration of Keycloak for SSO.</p>
        </div>
      `
    }));
  } else {
    res.send(renderPage({
      title: 'Keycloak Demo',
      user: null,
      body: `
        <div class="card shadow-sm p-4 mb-4 text-center">
          <h2 class="mb-3">Keycloak OIDC Demo</h2>
          <p class="lead">This application demonstrates how to integrate <strong>Keycloak</strong> for authentication.</p>
          <a href="/login" class="btn btn-primary btn-lg mt-3">Login with Keycloak</a>
        </div>
        <div class="card shadow-sm p-4">
          <h4>How it Works</h4>
          <ol class="mb-2">
            <li><strong>Login with Keycloak:</strong> Authenticate using your Keycloak credentials.</li>
            <li><strong>Access Granted:</strong> Upon successful authentication, you are logged in and can view your profile details.</li>
          </ol>
          <p class="text-muted">This demo showcases a seamless integration of Keycloak for SSO.</p>
        </div>
      `
    }));
  }
});

app.get('/login', (req, res, next) => {
  passport.authenticate('oidc', {
    prompt: 'login'
  })(req, res, next);
});

app.get('/callback', passport.authenticate('oidc', {
  successRedirect: '/',
  failureRedirect: '/error'
}));

app.get('/error', (req, res) => {
  res.status(401).send(renderPage({
    title: 'Error',
    user: null,
    body: `<div class="alert alert-danger"><h4>Authentication Failed</h4><p>There was a problem logging you in. <a href="/login" class="alert-link">Try again</a>.</p></div>`
  }));
});

app.get('/logout', async (req, res) => {
  try {
    // Revoke Keycloak session
    const keycloak = req.user && req.user._keycloak;
    if (keycloak && keycloak.idToken) {
      const endSessionUrl = `${process.env.OIDC_ISSUER}/protocol/openid-connect/logout?id_token_hint=${keycloak.idToken}&post_logout_redirect_uri=${encodeURIComponent(process.env.CALLBACK_URL)}`;
      await axios.get(endSessionUrl);
    }
    // Destroy local session
    req.logout(() => {
      req.session.destroy(() => {
        res.redirect('/');
      });
    });
  } catch (err) {
    req.logout(() => {
      req.session.destroy(() => {
        res.redirect('/');
      });
    });
  }
});

// Add body parser for form data (Express 4.16+)
app.use(express.urlencoded({ extended: true }));

app.listen(3000, () => console.log('Listening on http://localhost:3000'));
