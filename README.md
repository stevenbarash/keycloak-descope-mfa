# Keycloak OIDC Demo (Keycloak-Only Branch)

This project demonstrates how to use Keycloak as an OpenID Connect (OIDC) provider for authentication in a Node.js Express app. This branch (`keycloak-only`) removes all direct Descope logic and assumes Descope is federated with Keycloak, so all authentication and user info come from Keycloak.

## Features
- Login with Keycloak (OIDC)
- Session management with Passport.js
- User info display after login
- Clean Bootstrap UI

## Prerequisites
- Node.js (v18+ recommended)
- A running Keycloak instance (or any OIDC-compliant IdP)
- Keycloak client configured for OIDC
- (Optional) Descope federated with Keycloak (handled on IdP side, not in this code)

## Setup
1. **Clone the repository and switch to the keycloak-only branch:**
   ```sh
   git clone <repo-url>
   cd keycloak-descope-test
   git checkout keycloak-only
   ```

2. **Install dependencies:**
   ```sh
   npm install
   ```

3. **Configure environment variables:**
   Create a `.env` file in the root directory with the following:
   ```env
   OIDC_ISSUER=https://<your-keycloak-domain>/realms/<realm-name>
   CLIENT_ID=<your-client-id>
   CLIENT_SECRET=<your-client-secret>
   CALLBACK_URL=http://localhost:3000/callback
   ```
   - Adjust the URLs and credentials to match your Keycloak setup.

4. **Run the app:**
   ```sh
   node server.js
   ```
   The app will be available at [http://localhost:3000](http://localhost:3000)

## How it Works
- Users log in via Keycloak using OIDC.
- After authentication, user info is displayed on the home page.
- The app extracts the username and display name from the OIDC profile, including support for federated IdPs where user info may be nested.

## Notes
- This branch does **not** use Descope directly. If you want to use Descope for MFA, use the `main` branch.
- If Descope is federated with Keycloak, all user info and authentication will flow through Keycloak.

## License
MIT 