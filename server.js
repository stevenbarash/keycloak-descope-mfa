require('dotenv').config();
const express = require('express');
const passport = require('passport');
const OIDCStrategy = require('passport-openidconnect').Strategy;
const session = require('express-session');
const path = require('path');
const axios = require('axios');
const descope = require('@descope/node-sdk');

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

// Descope MFA Middleware
function requireDescopeMFA(req, res, next) {
  if (req.session.descopeMfaVerified) return next();
  res.redirect('/descope/mfa');
}

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
    requireDescopeMFA(req, res, () => {
      res.send(renderPage({
        title: 'Welcome',
        user: req.user,
        body: `
          <div class="card shadow-sm p-4 mb-4">
            <h2 class="mb-3">Welcome, ${req.user.displayName || req.user.id}!</h2>
            <p class="lead">You are logged in via <strong>Keycloak</strong> with <strong>Descope</strong> MFA.</p>
            <h5 class="mt-4">Your Authentication Details</h5>
            <pre class="bg-light p-3 rounded border">${JSON.stringify(req.user, null, 2)}</pre>
            <a href="/logout" class="btn btn-danger mt-3">Logout</a>
          </div>
          <div class="card shadow-sm p-4">
            <h4>How it Works</h4>
            <ol class="mb-2">
              <li><strong>Login with Keycloak:</strong> Authenticate using your Keycloak credentials.</li>
              <li><strong>MFA with Descope:</strong> After primary authentication, Descope enforces Multi-Factor Authentication (MFA) for enhanced security.</li>
              <li><strong>Access Granted:</strong> Upon successful MFA, you are logged in and can view your profile details above.</li>
            </ol>
            <p class="text-muted">This demo showcases a seamless integration of Keycloak for SSO and Descope for MFA.</p>
          </div>
        `
      }));
    });
  } else {
    res.send(renderPage({
      title: 'Keycloak + Descope MFA Demo',
      user: null,
      body: `
        <div class="card shadow-sm p-4 mb-4 text-center">
          <h2 class="mb-3">Keycloak + Descope MFA Demo</h2>
          <p class="lead">This application demonstrates how to integrate <strong>Keycloak</strong> for authentication and <strong>Descope</strong> for Multi-Factor Authentication (MFA).</p>
          <a href="/login" class="btn btn-primary btn-lg mt-3">Login with Keycloak</a>
        </div>
        <div class="card shadow-sm p-4">
          <h4>How it Works</h4>
          <ol class="mb-2">
            <li><strong>Login with Keycloak:</strong> Authenticate using your Keycloak credentials.</li>
            <li><strong>MFA with Descope:</strong> After primary authentication, Descope enforces Multi-Factor Authentication (MFA) for enhanced security.</li>
            <li><strong>Access Granted:</strong> Upon successful MFA, you are logged in and can view your profile details.</li>
          </ol>
          <p class="text-muted">This demo showcases a seamless integration of Keycloak for SSO and Descope for MFA.</p>
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

const descopeClient = descope({ projectId: process.env.DESCOPE_PROJECT_ID });

app.get('/descope/mfa', async (req, res) => {
  if (!req.isAuthenticated()) return res.redirect('/login');
  let userEmail = req.user.email;
  if (!userEmail && req.user.id) {
    if (typeof req.user.id === 'string') {
      userEmail = req.user.id;
    } else if (typeof req.user.id === 'object') {
      userEmail = req.user.id.username || (req.user.id.emails && req.user.id.emails[0] && req.user.id.emails[0].value);
    }
  }
  console.log('Descope MFA: userEmail', userEmail);
  if (!userEmail) {
    return res.status(400).send('No email or user ID found for MFA');
  }
  try {
    // Trigger a magic link for step-up MFA
    const redirectUrl = process.env.DESCOPE_REDIRECT_URL || `${process.env.CALLBACK_URL}/descope/callback`;
    await descopeClient.magicLink.signIn.email(userEmail, redirectUrl, { stepup: true });
    // Render a page instructing the user to check their email
    res.send(renderPage({
      title: 'Descope MFA',
      user: req.user,
      body: `
        <div class="alert alert-info mt-4">A magic link has been sent to <strong>${userEmail}</strong>. Please check your email and click the link to complete MFA.</div>
        <a href="/logout" class="btn btn-secondary mt-3">Cancel</a>
      `
    }));
  } catch (error) {
    console.error('Descope MFA initiation error:', error);
    res.status(500).send('Error initiating Descope MFA: ' + error.message);
  }
});

app.get('/descope/callback', async (req, res) => {
  const { token, error } = req.query;
  if (error) {
    return res.status(400).send('Descope MFA failed: ' + error);
  }
  if (!token || typeof token !== 'string') {
    return res.status(400).send('No magic link token provided');
  }
  try {
    // Validate the magic link token
    const validateResponse = await descopeClient.magicLink.signIn.verify({
      token,
    });
    if (!validateResponse.sessionJwt) {
      return res.status(401).send('No session token received');
    }
    await descopeClient.session.validate(validateResponse.sessionJwt);
    req.session.descopeMfaVerified = true;
    res.redirect('/');
  } catch (err) {
    console.error('Descope MFA validation error:', err);
    res.status(401).send('Descope MFA validation failed');
  }
});

app.get('/logout', async (req, res) => {
  try {
    // Revoke Keycloak session
    const keycloak = req.user && req.user._keycloak;
    if (keycloak && keycloak.idToken) {
      const endSessionUrl = `${process.env.OIDC_ISSUER}/protocol/openid-connect/logout?id_token_hint=${keycloak.idToken}&post_logout_redirect_uri=${encodeURIComponent(process.env.CALLBACK_URL)}`;
      await axios.get(endSessionUrl);
    }
    // Destroy local session and Descope MFA flag
    req.logout(() => {
      req.session.descopeMfaVerified = false;
      req.session.destroy(() => {
        res.redirect('/');
      });
    });
  } catch (err) {
    req.logout(() => {
      req.session.descopeMfaVerified = false;
      req.session.destroy(() => {
        res.redirect('/');
      });
    });
  }
});

// Add body parser for form data (Express 4.16+)
app.use(express.urlencoded({ extended: true }));

app.listen(3000, () => console.log('Listening on http://localhost:3000'));
