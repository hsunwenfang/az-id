



═══════════════════════════════════════════════════════════════════════════
 PHASE 0: SETUP (before any HTTP traffic)
═══════════════════════════════════════════════════════════════════════════

Web App (at startup or when session missing):
  1. Generate code_verifier = random 43-128 char string
     e.g. "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
  2. Compute code_challenge = Base64url(SHA-256(code_verifier))
     e.g. "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
  3. Generate state = random string (CSRF nonce)
     e.g. "xyz123"
  4. Generate nonce = random string (OIDC replay protection)
     e.g. "n-0S6_WzA2Mj"
  5. Store in server session: { state, nonce, code_verifier, original_url }


═══════════════════════════════════════════════════════════════════════════
 PHASE 1: USER REQUESTS PROTECTED PAGE
═══════════════════════════════════════════════════════════════════════════

User          Browser                Web App                  Entra ID
 │               │                      │                        │
 │  clicks link  │                      │                        │
 │──────────────►│                      │                        │
 │               │                      │                        │
 │               │  GET /dashboard      │                        │
 │               │  Cookie: (none)      │                        │
 │               │─────────────────────►│                        │
 │               │                      │                        │
 │               │                      │ Check: session cookie? │
 │               │                      │ → NO → redirect to IdP│
 │               │                      │                        │


═══════════════════════════════════════════════════════════════════════════
 PHASE 2: FIRST 302 — Web App → Browser → Entra ID
═══════════════════════════════════════════════════════════════════════════

 │               │  HTTP 302 Found      │                        │
 │               │◄─────────────────────│                        │
 │               │                      │                        │
 │               │  Location: https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize
 │               │    ?client_id=abc-123-def                     │
 │               │    &response_type=code                        │
 │               │    &redirect_uri=https://myapp.com/callback   │
 │               │    &scope=openid profile offline_access https://graph.microsoft.com/Mail.Read
 │               │    &state=xyz123                              │
 │               │    &nonce=n-0S6_WzA2Mj                       │
 │               │    &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
 │               │    &code_challenge_method=S256                │
 │               │    &response_mode=query                       │
 │               │                      │                        │

What travels in this 302:
  ✅ client_id          — app's identity (from app registration)
  ✅ scope              — what access is needed (defined by resource server)
  ✅ state              — CSRF token (client will verify on return)
  ✅ nonce              — replay protection (will appear inside id_token)
  ✅ code_challenge     — PKCE hash (auth server stores it)
  ✅ redirect_uri       — where to send the code back
  ❌ code_verifier      — NOT here (stays on server, used later)
  ❌ client_secret      — NOT here (never in browser)
  ❌ any tokens         — NOT here (don't exist yet)


═══════════════════════════════════════════════════════════════════════════
 PHASE 3: BROWSER FOLLOWS 302 → ENTRA ID LOGIN
═══════════════════════════════════════════════════════════════════════════

 │               │  GET /oauth2/v2.0/authorize?...               │
 │               │──────────────────────────────────────────────►│
 │               │                      │                        │
 │               │                      │   Entra ID does:       │
 │               │                      │   1. Validate client_id exists
 │               │                      │   2. Validate redirect_uri matches registration
 │               │                      │   3. Parse scope → determine resource server
 │               │                      │   4. STORE: { code_challenge, code_challenge_method }
 │               │                      │   5. Return login page  │
 │               │                      │                        │
 │               │  HTTP 200            │                        │
 │               │  Content-Type: text/html                      │
 │               │◄──────────────────────────────────────────────│
 │◄──────────────│  (login page)        │                        │
 │               │                      │                        │
 │  enters email │                      │                        │
 │──────────────►│                      │                        │
 │               │  POST /login (email) │                        │
 │               │──────────────────────────────────────────────►│
 │               │                      │                        │
 │               │                      │  (may 302 to home realm│
 │               │                      │   discovery, AD FS,    │
 │               │                      │   or continue here)    │
 │               │                      │                        │
 │  enters password                     │                        │
 │──────────────►│                      │                        │
 │               │  POST /login (pwd)   │                        │
 │               │──────────────────────────────────────────────►│
 │               │                      │                        │
 │               │                      │   Entra ID does:       │
 │               │                      │   1. Validate password (PHS/PTA/Federation)
 │               │                      │   2. Check Conditional Access policies
 │               │                      │      → signals: user, app, location, device, risk
 │               │                      │      → decision: require MFA?  │
 │               │                      │                        │
 │               │  MFA challenge page  │                        │
 │               │◄──────────────────────────────────────────────│
 │◄──────────────│                      │                        │
 │               │                      │                        │
 │  approves MFA (Authenticator push / FIDO2 / TOTP)            │
 │──────────────►│                      │                        │
 │               │  POST /mfa-verify    │                        │
 │               │──────────────────────────────────────────────►│
 │               │                      │                        │
 │               │                      │   Entra ID does:       │
 │               │                      │   1. Verify MFA        │
 │               │                      │   2. Re-evaluate CA policies (all satisfied?)
 │               │                      │   3. Check consent: has user/admin consented to scopes?
 │               │                      │      → if not: show consent screen
 │               │                      │      → if yes: proceed │
 │               │                      │   4. Generate AUTH_CODE │
 │               │                      │   5. Bind to code_challenge:
 │               │                      │      ┌────────────────────────────────────────┐
 │               │                      │      │ AUTH_CODE record:                      │
 │               │                      │      │   code: "AUTH_CODE_VALUE"              │
 │               │                      │      │   client_id: "abc-123-def"             │
 │               │                      │      │   redirect_uri: "https://myapp.com/cb" │
 │               │                      │      │   scope: "openid profile offline_access│
 │               │                      │      │           Mail.Read"                   │
 │               │                      │      │   code_challenge: "E9Melh..."          │
 │               │                      │      │   code_challenge_method: "S256"        │
 │               │                      │      │   user: alice@contoso.com              │
 │               │                      │      │   nonce: "n-0S6_WzA2Mj"               │
 │               │                      │      │   expires: now + 10 min               │
 │               │                      │      │   used: false                          │
 │               │                      │      └────────────────────────────────────────┘


═══════════════════════════════════════════════════════════════════════════
 PHASE 4: SECOND 302 — Entra ID → Browser → Web App /callback
═══════════════════════════════════════════════════════════════════════════

 │               │  HTTP 302 Found      │                        │
 │               │◄──────────────────────────────────────────────│
 │               │  Location: https://myapp.com/callback         │
 │               │    ?code=AUTH_CODE_VALUE                       │
 │               │    &state=xyz123                              │
 │               │    &session_state=...                         │
 │               │                      │                        │

What travels in this 302:
  ✅ code              — authorization code (one-use, ~10 min TTL)
  ✅ state             — echoed back unchanged (for client CSRF check)
  ❌ access_token      — NOT here
  ❌ id_token          — NOT here
  ❌ refresh_token     — NOT here
  ❌ code_verifier     — NOT here
  ❌ client_secret     — NOT here

 │               │  GET /callback?code=AUTH_CODE_VALUE&state=xyz123
 │               │─────────────────────►│                        │
 │               │                      │                        │


═══════════════════════════════════════════════════════════════════════════
 PHASE 5: BACK-CHANNEL — Web App → Entra ID /token (server-to-server)
═══════════════════════════════════════════════════════════════════════════

 │               │                      │                        │
 │               │                      │  Web App does:         │
 │               │                      │  1. Verify state == "xyz123" (CSRF check)
 │               │                      │     → matches stored value? ✅
 │               │                      │                        │
 │               │                      │  2. POST https://login.microsoftonline.com/
 │               │                      │     {tenant}/oauth2/v2.0/token
 │               │                      │                        │
 │               │                      │     Content-Type: application/x-www-form-urlencoded
 │               │                      │                        │
 │               │                      │     grant_type=authorization_code
 │               │                      │     &code=AUTH_CODE_VALUE
 │               │                      │     &redirect_uri=https://myapp.com/callback
 │               │                      │     &client_id=abc-123-def
 │               │                      │     &client_secret=MY_SECRET     ← confidential client
 │               │                      │     &code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
 │               │                      │                        │
 │               │                      │───────────────────────►│
 │               │                      │                        │
 │               │                      │   Entra ID /token does:│
 │               │                      │                        │
 │               │                      │   1. Look up AUTH_CODE_VALUE
 │               │                      │      → found? ✅       │
 │               │                      │      → already used? ❌ (first use)
 │               │                      │      → expired? ❌ (within 10 min)
 │               │                      │                        │
 │               │                      │   2. Verify client_id matches
 │               │                      │      → "abc-123-def" == "abc-123-def" ✅
 │               │                      │                        │
 │               │                      │   3. Verify redirect_uri matches
 │               │                      │      → exact string match ✅
 │               │                      │                        │
 │               │                      │   4. Verify client_secret (or cert)
 │               │                      │      → proves caller is the real app ✅
 │               │                      │                        │
 │               │                      │   5. PKCE verification:│
 │               │                      │      compute = Base64url(SHA-256(code_verifier))
 │               │                      │      compare = stored code_challenge
 │               │                      │                        │
 │               │                      │      Base64url(SHA-256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"))
 │               │                      │      = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
 │               │                      │      == stored code_challenge? ✅
 │               │                      │                        │
 │               │                      │   6. Mark AUTH_CODE as used (one-time)
 │               │                      │                        │
 │               │                      │   7. Mint tokens:      │
 │               │                      │                        │


═══════════════════════════════════════════════════════════════════════════
 PHASE 6: TOKEN RESPONSE (back-channel, server-to-server)
═══════════════════════════════════════════════════════════════════════════

 │               │                      │  HTTP 200 OK           │
 │               │                      │  Content-Type: application/json
 │               │                      │◄───────────────────────│
 │               │                      │                        │
 │               │                      │  {                     │
 │               │                      │    "token_type": "Bearer",
 │               │                      │                        │
 │               │                      │    "access_token": "eyJ...═══════════════════╗
 │               │                      │         │              │                     ║
 │               │                      │         │  JWT payload:                      ║
 │               │                      │         │  {                                 ║
 │               │                      │         │    "aud": "https://graph.microsoft.com", ← FOR RESOURCE SERVER
 │               │                      │         │    "iss": "https://login.microsoftonline.com/{tenant}/v2.0",
 │               │                      │         │    "sub": "alice-object-id",       ║
 │               │                      │         │    "appid": "abc-123-def",         ║
 │               │                      │         │    "scp": "Mail.Read profile openid", ← delegated scopes
 │               │                      │         │    "exp": 1713700000,  (now + 1hr) ║
 │               │                      │         │    "iat": 1713696400               ║
 │               │                      │         │  }                                 ║
 │               │                      │         │              │                     ║
 │               │                      │         ╚══════════════════════════════════════╝
 │               │                      │                        │
 │               │                      │    "id_token": "eyJ...═══════════════════════╗
 │               │                      │         │              │                     ║
 │               │                      │         │  JWT payload:                      ║
 │               │                      │         │  {                                 ║
 │               │                      │         │    "aud": "abc-123-def",  ← FOR THE CLIENT APP
 │               │                      │         │    "iss": "https://login.microsoftonline.com/{tenant}/v2.0",
 │               │                      │         │    "sub": "alice-object-id",       ║
 │               │                      │         │    "name": "Alice Smith",          ║
 │               │                      │         │    "email": "alice@contoso.com",   ║
 │               │                      │         │    "nonce": "n-0S6_WzA2Mj", ← MUST match what client sent
 │               │                      │         │    "exp": 1713700000               ║
 │               │                      │         │  }                                 ║
 │               │                      │         ╚══════════════════════════════════════╝
 │               │                      │                        │
 │               │                      │    "refresh_token": "0.ARwA..."  ← opaque string
 │               │                      │         │              │
 │               │                      │         │  Properties: │
 │               │                      │         │  - Opaque (not JWT, not decodable)
 │               │                      │         │  - Long-lived (~90 days, sliding)
 │               │                      │         │  - Bound to client_id + user + scope
 │               │                      │         │  - One-use with rotation (new RT each refresh)
 │               │                      │         │  - Revocable server-side
 │               │                      │         │  - Only issued because scope included "offline_access"
 │               │                      │                        │
 │               │                      │    "expires_in": 3600  │
 │               │                      │  }                     │


═══════════════════════════════════════════════════════════════════════════
 PHASE 7: WEB APP VALIDATES AND CREATES SESSION
═══════════════════════════════════════════════════════════════════════════

 │               │                      │                        │
 │               │                      │  Web App does:         │
 │               │                      │                        │
 │               │                      │  1. Validate id_token: │
 │               │                      │     a. Verify JWT signature (RS256)
 │               │                      │        using JWKS from /.well-known/openid-configuration
 │               │                      │     b. Verify iss == expected issuer
 │               │                      │     c. Verify aud == "abc-123-def" (my client_id)
 │               │                      │     d. Verify exp > now
 │               │                      │     e. Verify nonce == "n-0S6_WzA2Mj" (replay check)
 │               │                      │                        │
 │               │                      │  2. Extract identity:  │
 │               │                      │     user = alice@contoso.com
 │               │                      │     name = "Alice Smith"
 │               │                      │                        │
 │               │                      │  3. Store server-side: │
 │               │                      │     session[alice] = { │
 │               │                      │       access_token,    │
 │               │                      │       refresh_token,   │
 │               │                      │       token_expiry,    │
 │               │                      │       user_info        │
 │               │                      │     }                  │
 │               │                      │                        │
 │               │                      │  4. Generate session cookie (opaque ID)


═══════════════════════════════════════════════════════════════════════════
 PHASE 8: THIRD 302 — Web App → Browser → original page
═══════════════════════════════════════════════════════════════════════════

 │               │  HTTP 302 Found      │                        │
 │               │◄─────────────────────│                        │
 │               │  Location: /dashboard│                        │
 │               │  Set-Cookie: session=OPAQUE_SESSION_ID;       │
 │               │              HttpOnly; Secure; SameSite=Lax   │
 │               │                      │                        │

What travels in this 302:
  ✅ session cookie     — opaque ID (not a token, just a session key)
  ❌ access_token       — NOT here (stored server-side)
  ❌ id_token           — NOT here (already consumed)
  ❌ refresh_token      — NOT here (stored server-side)

 │               │  GET /dashboard      │                        │
 │               │  Cookie: session=OPAQUE_SESSION_ID            │
 │               │─────────────────────►│                        │
 │               │                      │                        │
 │               │                      │  Look up session → found
 │               │                      │  User = Alice ✅       │
 │               │                      │                        │
 │               │  HTTP 200            │                        │
 │◄──────────────│◄─────────────────────│                        │
 │  sees dashboard                      │                        │


═══════════════════════════════════════════════════════════════════════════
 PHASE 9: API CALL (Web App uses access_token)
═══════════════════════════════════════════════════════════════════════════

 │               │                      │                        │
 │               │                      │  GET https://graph.microsoft.com/v1.0/me/messages
 │               │                      │  Authorization: Bearer eyJ...(access_token)
 │               │                      │──────────────────────────────────►│
 │               │                      │                        │  Graph API
 │               │                      │                        │  validates:
 │               │                      │                        │  1. Signature
 │               │                      │                        │  2. aud == graph.microsoft.com
 │               │                      │                        │  3. exp > now
 │               │                      │                        │  4. scp includes Mail.Read
 │               │                      │                        │  5. Return mail data
 │               │                      │◄─────────────────────────────────│
 │               │                      │  { "value": [...mail...] }      │


═══════════════════════════════════════════════════════════════════════════
 PHASE 10: TOKEN REFRESH (when access_token expires)
═══════════════════════════════════════════════════════════════════════════

 │               │                      │                        │
 │               │                      │  access_token expired  │
 │               │                      │  (exp < now)           │
 │               │                      │                        │
 │               │                      │  POST /oauth2/v2.0/token
 │               │                      │    grant_type=refresh_token
 │               │                      │    &refresh_token=0.ARwA...
 │               │                      │    &client_id=abc-123-def
 │               │                      │    &client_secret=MY_SECRET
 │               │                      │    &scope=openid profile offline_access Mail.Read
 │               │                      │───────────────────────►│
 │               │                      │                        │
 │               │                      │  Response:             │
 │               │                      │  {                     │
 │               │                      │    "access_token": "eyJ...(NEW)",
 │               │                      │    "id_token": "eyJ...(NEW, optional)",
 │               │                      │    "refresh_token": "0.ARwA...(NEW, rotated)",
 │               │                      │    "expires_in": 3600  │
 │               │                      │  }                     │
 │               │                      │◄───────────────────────│
 │               │                      │                        │
 │               │                      │  Old refresh_token is now INVALID
 │               │                      │  Store new tokens in session