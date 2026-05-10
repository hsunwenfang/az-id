

# Glossary




# Identity & Access Management: Protocols, Patterns, Network, and Azure Implementation

OAuth2.0
https://www.rfc-editor.org/rfc/rfc9700

# Aspects

## Token Canonical

- Canonical -> One unambiguous representation
- JSON is loose in dtype and seq -> same data can hash differently
- X.509 and Keberos requires Canonical encoding
- schema-strict ASN.1 DER encoding is Canonical
- JWS signs the JWT aka the "." concatenated base64url-encoded header & payload
- Oppositely, XML C14N (W3C) normalizes XML byte representation before hash
- XSD enforces Schema for security 

## Token Formats

**ASN.1 (DER/BER)** — binary, compact, crypto-canonical. Used by Kerberos, X.509, LDAP, OCSP, PKCS.  
**XML** — human-readable, self-describing, strong tooling. Used by SAML 2.0, WS-Federation, SOAP.  
**JSON / JWT** — lightweight, browser-native, developer-friendly. Used by OAuth 2.0, OIDC, FIDO2 attestation metadata.  
**CBOR** — compact modern binary, not ASN.1. Used by FIDO2/WebAuthn authenticator data.

| Property | ASN.1 DER | XML | JSON / JWT |
|---|---|---|---|
| Wire size | Compact binary | Verbose | Moderate (Base64url for JWT) |
| Human-readable | No | Yes | Yes |
| Canonical encoding | Yes (DER) | No | No (requires JCS/JWS) |
| Crypto-friendly | Yes — deterministic bytes for signing | Partial (C14N needed) | No inherent canonical form |
| Developer ergonomics | Low — needs ASN.1 compiler + schema | Medium — verbose but parseable | High — native in every language |
| Era / context | Network/OS protocols (pre-web) | Enterprise web services (late 1990s–2000s) | REST/browser era (2010s–present) |

**Why ASN.1 was not replaced for PKI/Kerberos**: cryptographic signatures require a canonical (exact, deterministic) byte representation — DER provides this. JSON has no canonical encoding by default. X.509 certificates and Kerberos tickets carry signed/encrypted blobs where byte-for-byte determinism is mandatory.

**Why JSON won for application protocols**: bandwidth became cheap, developer ergonomics beat wire efficiency, and browser ecosystems made JSON the universal interchange format.

## Attack Surface

## Authn

### Keberos

https://www.rfc-editor.org/rfc/rfc4120

- 1 AS-REQ
    - 3.1.1 + 5.4.1
- 2 AS-REP
    - 3.1.3 + 5.4.2
- 3 TGS-REQ
    - 3.3.1 + 5.4.1 + 5.5.1
- 4 TGS-REP
    - 3.3.3 + 5.4.2

| Aspect | Kerberos | NTLM (challenge-response) | PKI / X.509 CBA | FIDO2 / WebAuthn | LDAP bind (password) |
|---|---|---|---|---|---|
| Trust anchor | KDC (shared symmetric keys) | Domain Controller | Certificate Authority (CA chain) | Per-RP key pair (no central trust) | Directory server |
| Credential type | Symmetric ticket (encrypted with service key) | HMAC challenge-response | X.509 certificate + private key | Public/private key pair per origin | Password (plaintext or hashed) |
| Network requirement | Line-of-sight to KDC (port 88) | Line-of-sight to DC | CRL/OCSP endpoint reachable | None after registration | Line-of-sight to LDAP server |
| Replay protection | Authenticator timestamp (±5 min clock skew) | Nonce in challenge | Nonce in TLS handshake | Challenge signed per-ceremony | None inherent |
| Delegation | Native (constrained/unconstrained/RBCD) | Limited (S4U2Self) | Via proxy certificates | Not applicable | Not applicable |
| Cross-domain | Cross-realm trusts (explicit, forest trusts) | Requires NTLM pass-through | Any CA in trusted store | Per-RP scoped; no cross-domain concept | No |
| Phishing resistance | No (credential theft via ticket extraction) | No (pass-the-hash) | Partial (cert theft possible) | Yes (origin-bound) | No |
| Where used today | Windows domain, on-prem apps, Seamless SSO, KCD | Legacy Windows, NTLMv2 fallback | Smart card, Azure CBA, mTLS | Passkeys, hardware security keys | On-prem app auth, AD bind |
| Main weakness | Kerberoasting, AS-REP roasting, ticket theft | Pass-the-hash, relay attacks | Private key theft, CA compromise | Device loss (mitigated by backup/sync) | Password spray, credential stuffing |

### PKI

Client                                                    Server
  │                                                          │
  │═══════════════ TLS 1.3 Handshake ════════════════════════│
  │                                                          │
  │──── ClientHello ────────────────────────────────────────►│
  │     - TLS version (1.3)                                  │
  │     - client_random (32 bytes)                           │
  │     - supported cipher suites                            │
  │     - supported signature algorithms                     │
  │     - key_share (client's ECDH public key)               │
  │     - supported_groups (e.g. X25519, P-256)              │
  │                                                          │
  │◄─── ServerHello ────────────────────────────────────────│
  │     - server_random (32 bytes)                           │
  │     - chosen cipher suite                                │
  │     - key_share (server's ECDH public key)               │
  │                                                          │
  │   ══ Both sides now derive session keys ══               │
  │      from (client_random + server_random                 │
  │            + ECDH shared secret)                         │
  │   ══ Everything below is ENCRYPTED ══════                │
  │                                                          │
  │◄─── EncryptedExtensions ────────────────────────────────│
  │     - server's additional negotiated parameters          │
  │       (ALPN protocol, server name, etc.)                 │
  │                                                          │
  │◄─── CertificateRequest ─────────────────────────────────│
  │     - server asks client to authenticate                 │
  │     - acceptable CA names                                │
  │     - acceptable signature algorithms                    │
  │                                                          │
  │◄─── Certificate (server) ───────────────────────────────│
  │     - server's cert chain:                               │
  │       [server leaf cert]                                 │
  │         subject: CN=server.contoso.com                   │
  │         subjectPublicKeyInfo: <server public key>        │
  │         AuthorityKeyIdentifier: → Intermediate CA        │
  │         signatureValue: Sign(IntermCA_priv, Hash(tbs))   │
  │       [intermediate CA cert]                             │
  │         AuthorityKeyIdentifier: → Root CA               │
  │         signatureValue: Sign(RootCA_priv, Hash(tbs))     │
  │                                                          │
  │   Client verifies server cert chain:                     │
  │     1. Verify intermediate sig with Root CA public key   │
  │     2. Verify leaf sig with Intermediate CA public key   │
  │     3. Check validity period, SAN matches hostname       │
  │     4. CRL/OCSP check on leaf cert                       │
  │                                                          │
  │◄─── CertificateVerify (server) ─────────────────────────│
  │     Sign(server_private_key,                             │
  │          Hash(full handshake transcript so far))         │
  │                                                          │
  │   Client verifies:                                       │
  │     Verify(server_public_key,          ← from cert above │
  │            CertificateVerify,                            │
  │            Hash(transcript))                             │
  │     → proves server owns the private key                 │
  │                                                          │
  │◄─── Finished (server) ──────────────────────────────────│
  │     HMAC(server_finished_key,                            │
  │          Hash(full transcript))                          │
  │                                                          │
  │   Client verifies Finished:                              │
  │     recomputes HMAC with its own finished_key            │
  │     → confirms transcript integrity + same session keys  │
  │                                                          │
  │──── Certificate (client) ───────────────────────────────►│
  │     - client's cert chain:                               │
  │       [Alice's leaf cert]                                │
  │         subject: CN=Alice                                │
  │         subjectPublicKeyInfo: <Alice's public key>       │
  │         SubjectAltName: UPN=alice@contoso.com            │
  │         AuthorityKeyIdentifier: → Intermediate CA        │
  │         signatureValue: Sign(IntermCA_priv, Hash(tbs))   │
  │       [intermediate CA cert]                             │
  │                                                          │
  │   Server verifies client cert chain:                     │
  │     1. Verify chain up to a trusted root CA              │
  │     2. Check validity, EKU = clientAuthentication        │
  │     3. CRL/OCSP check                                    │
  │     4. Map SubjectAltName UPN → user account             │
  │                                                          │
  │──── CertificateVerify (client) ─────────────────────────►│
  │     Sign(Alice_private_key,                              │
  │          Hash(full handshake transcript so far))         │
  │                                                          │
  │                         Server verifies:                 │
  │                           Verify(Alice_public_key,  ← from cert │
  │                                  CertificateVerify,      │
  │                                  Hash(transcript))       │
  │                           → proves Alice owns private key│
  │                                                          │
  │──── Finished (client) ──────────────────────────────────►│
  │     HMAC(client_finished_key,                            │
  │          Hash(full transcript))                          │
  │                                                          │
  │                         Server verifies Finished:        │
  │                           recomputes HMAC                │
  │                           → transcript integrity confirmed│
  │                                                          │
  │═══════════════ Handshake Complete ═══════════════════════│
  │                                                          │
  │◄══► Application Data (encrypted with session keys) ◄═══►│


## Authz

## OIDC Token Flow

┌─────────────────────────────────────────────────────────────────┐
│                        OIDC Token Flow                          │
│                                                                 │
│  Client ──── Authorization Code ────► Token Endpoint           │
│                                              │                  │
│                                    ┌─────────┴──────────┐      │
│                                    ▼                    ▼      │
│                              id_token            access_token  │
└─────────────────────────────────────────────────────────────────┘

┌──────────────────────────────┐   ┌──────────────────────────────┐
│         id_token             │   │        access_token          │
├──────────────────────────────┤   ├──────────────────────────────┤
│ Purpose:                     │   │ Purpose:                     │
│  Prove WHO the user is       │   │  Authorize access to a       │
│  (authentication assertion)  │   │  resource API                │
├──────────────────────────────┤   ├──────────────────────────────┤
│ Audience (aud):              │   │ Audience (aud):              │
│  The CLIENT app itself       │   │  The RESOURCE SERVER (API)   │
│  e.g. "my-spa-app-id"        │   │  e.g. "api://my-api"         │
├──────────────────────────────┤   ├──────────────────────────────┤
│ Consumed by:                 │   │ Consumed by:                 │
│  The client — reads claims   │   │  The API — validates and     │
│  to know who logged in       │   │  enforces permissions        │
├──────────────────────────────┤   ├──────────────────────────────┤
│ Must contain:                │   │ Must contain:                │
│  sub, iss, aud, exp, iat     │   │  sub, iss, aud, exp, scp/    │
│  nonce (if sent in request)  │   │  roles, appid                │
│  + identity claims:          │   │  + permission claims:        │
│  name, email, preferred_upn  │   │  scp (delegated)             │
│  acr, amr, auth_time         │   │  roles (application)         │
├──────────────────────────────┤   ├──────────────────────────────┤
│ Format:                      │   │ Format:                      │
│  Always JWT (readable)       │   │  JWT or OPAQUE string        │
│                              │   │  (API doesn't care, just     │
│                              │   │   validates it)              │
├──────────────────────────────┤   ├──────────────────────────────┤
│ Security rule:               │   │ Security rule:               │
│  NEVER send to an API        │   │  NEVER use to identify user  │
│  (it's for the client only)  │   │  (use id_token for that)     │
└──────────────────────────────┘   └──────────────────────────────┘

          OAuth 2.0 alone              OIDC adds
          issues access_token    ───►  id_token on top

### OAuth 2.0 Authorization code flow

User        Browser              Web App                    Entra ID (IdP)
 │              │                    │                           │
 │  GET /page   │                    │                           │
 │─────────────►│                    │                           │
 │              │  GET /page         │                           │
 │              │───────────────────►│                           │
 │              │                    │ "no session, need auth"   │
 │              │                    │                           │
 │              │  HTTP 302          │                           │
 │              │◄───────────────────│                           │
 │              │  Location:         │                           │
 │              │  https://login.microsoftonline.com/            │
 │              │    ?client_id=abc                              │
 │              │    &redirect_uri=https://myapp.com/callback    │
 │              │    &response_type=code                         │
 │              │    &scope=openid profile                       │
 │              │    &state=xyz123   │                           │
 │              │    &code_challenge=ABC (PKCE)                  │
 │              │                    │                           │
 │              │  GET (follows 302) │                           │
 │              │──────────────────────────────────────────────►│
 │              │                    │                           │
 │◄─────────────│  login page HTML   │                           │
 │              │◄──────────────────────────────────────────────│
 │              │                    │                           │
 │  enters credentials + MFA         │                           │
 │─────────────────────────────────────────────────────────────►│
 │              │                    │  validates credentials    │
 │              │                    │                           │
 │              │  HTTP 302          │                           │
 │              │◄──────────────────────────────────────────────│
 │              │  Location:         │                           │
 │              │  https://myapp.com/callback                    │
 │              │    ?code=AUTH_CODE │                           │
 │              │    &state=xyz123   │                           │
 │              │                    │                           │
 │              │  GET /callback     │                           │
 │              │    ?code=AUTH_CODE │                           │
 │              │    &state=xyz123   │                           │
 │              │───────────────────►│                           │
 │              │                    │ 1. verify state==xyz123   │
 │              │                    │ 2. POST /token            │
 │              │                    │    code=AUTH_CODE         │
 │              │                    │    code_verifier (PKCE)   │
 │              │                    │    client_secret          │
 │              │                    │───────────────────────────►
 │              │                    │                           │
 │              │                    │    access_token           │
 │              │                    │    id_token               │
 │              │                    │    refresh_token          │
 │              │                    │◄──────────────────────────│
 │              │                    │ 3. validate id_token      │
 │              │                    │ 4. create session         │
 │              │                    │                           │
 │              │  HTTP 302          │                           │
 │              │◄───────────────────│                           │
 │              │  Location: /page   │                           │
 │              │  Set-Cookie: session=...                       │
 │              │                    │                           │
 │              │  GET /page         │                           │
 │              │───────────────────►│                           │
 │              │  (with session     │                           │
 │              │   cookie)          │                           │
 │◄─────────────│  authenticated     │                           │
 │              │  page HTML ◄───────│                           │


Key observations:
  - AUTH_CODE travels through browser (URL) — short-lived, one-use
  - access_token NEVER touches the browser — server-to-server only
  - state param travels out and back through browser — CSRF check
  - The /callback endpoint is the redirect_uri — app code, not a page
  - Final 302 to /page is how app sends user to their original destination







---

## 1. Protocols and Design Patterns for AuthN/AuthZ

### 1.1 Core Authentication Protocols

**OAuth 2.0**
- Authorization framework (RFC 6749) separating resource owner, client, authorization server, and resource server.
- Issues short-lived access tokens (JWT or opaque) and optional refresh tokens.
    - JWT and opaque 
- Scopes define the granularity of access granted to a client.
- Not an authentication protocol by itself — identity is layered on top via OpenID Connect.

**OpenID Connect (OIDC)**
- Identity layer built on top of OAuth 2.0 (adds `id_token` as a JWT).
- Standardizes claims: `sub`, `iss`, `aud`, `exp`, `iat`, `nonce`, `email`, `name`.
- Discovery endpoint (`/.well-known/openid-configuration`) publishes signing keys and supported flows.
- UserInfo endpoint allows clients to fetch additional claims post-authentication.

**SAML 2.0**
- XML-based federation protocol for SSO between identity providers (IdP) and service providers (SP).
- Two primary bindings: HTTP Redirect (GET, for AuthnRequest) and HTTP POST (for assertions).
- Assertions carry AuthnStatement, AttributeStatement, and AuthzDecisionStatement.
- Signature and encryption are applied to assertions (or full response) using X.509 certificates.
- Metadata exchange (SP metadata ↔ IdP metadata) establishes trust and endpoint configuration.

**WS-Federation**
- Passive federation protocol used heavily in Microsoft (ADFS, SharePoint, Dynamics).
- Uses Security Token Service (STS) to issue tokens; tokens returned in WS-Trust format.
- Supports WS-Trust active profiles for programmatic (non-browser) token acquisition.

**Kerberos**
- Ticket-based protocol for intra-domain authentication (RFC 4120).
- KDC (Key Distribution Center) issues TGTs; service tickets are presented to resources.
- Used by AD DS for Windows-joined device authentication and seamless SSO.
- Forwardable tickets enable delegation (constrained, unconstrained, resource-based constrained).

**FIDO2 / WebAuthn / Passkeys**
- W3C WebAuthn spec + FIDO Alliance CTAP2 protocol for passwordless strong authentication.
- Authenticators (platform or roaming/cross-device) generate public/private key pairs per RP.
- Authentication ceremony: server issues challenge → authenticator signs with private key → server verifies.
- Resident keys (discoverable credentials) enable usernameless login.
- Passkeys extend FIDO2 with cross-device sync via cloud keychain (iCloud Keychain, Google Password Manager).

**TOTP / HOTP (RFC 6238 / RFC 4226)**
- Hardware OATH tokens and authenticator apps generate time-based or HMAC-based OTPs.
- Shared secret seeded during enrollment; server validates within a time window (±1 step).
- HOTP is counter-based; TOTP is time-based (30-second step size standard).

**RADIUS (RFC 2865)**
- UDP-based AAA protocol used by NPS (Network Policy Server) for network device authentication.
- MFA can be injected via the Azure MFA NPS extension, which intercepts RADIUS Access-Request messages.
- Shared secret between NAS and RADIUS server must be secured; prefer RADIUS over TLS (RadSec).

---

### 1.2 OAuth 2.0 Authorization Flows

| Flow | Use Case | Token Endpoint? | User Interaction? |
|---|---|---|---|
| Authorization Code + PKCE | Public clients (SPAs, mobile) | Yes | Yes |
| Authorization Code (confidential) | Web apps with server side | Yes | Yes |
| Client Credentials | Daemon / service-to-service | Yes | No |
| Device Authorization (Device Code) | Input-constrained devices | Yes | Yes (on second device) |
| On-Behalf-Of (OBO) | Middle-tier API calling downstream API | Yes | No |
| Implicit (legacy) | Deprecated — superseded by Auth Code + PKCE | No | Yes |
| Resource Owner Password Credentials (ROPC) | Legacy migration only — avoid | Yes | No (credentials passed directly) |

**Key Design Decisions:**
- Always use PKCE with Authorization Code flow for public clients, even when a client secret exists.
- Prefer short-lived access tokens (≤1 hour); use refresh tokens with rotation.
- Audience (`aud`) validation on the resource server prevents token replay across services.
- State parameter in Authorization Code flow provides CSRF protection; nonce prevents replay in OIDC.

---

### 1.3 Token Patterns and JWT Security

- **JWT structure**: Header (alg, kid) . Payload (claims) . Signature — all Base64URL encoded.
- Always validate: signature, `iss`, `aud`, `exp`, `nbf`, `nonce` (for OIDC id_tokens).
- Prefer RS256 (asymmetric) over HS256 (symmetric shared secret) for multi-party verification.
- Rotate signing keys regularly; use JWKS endpoint (`/discovery/v2.0/keys`) for dynamic key retrieval.
- Avoid storing access tokens in `localStorage`; use httpOnly cookies or in-memory for SPAs.
- Token revocation: OAuth has no universal revocation for access tokens — keep TTL short; use refresh token revocation.



---

### 1.4 Design Patterns for AuthZ

**Role-Based Access Control (RBAC)**
- Assign permissions to roles, assign roles to principals.
- Flat or hierarchical role structures; minimize role explosion by using fine-grained scopes.
- Azure AD App Roles enable application-level RBAC via manifest and token claims.

**Attribute-Based Access Control (ABAC)**
- Policies evaluate attributes of subject, resource, environment, and action.
- More expressive than RBAC; supports conditions (e.g., "allow if department=Finance AND sensitivity=Low").
- Azure ABAC conditions extend Azure RBAC role assignments with attribute filters on storage resources.

**Claims-Based Identity**
- Identity is expressed as a set of claims issued by a trusted authority.
- Claims transformation at the federation boundary (AD FS claims issuance rules, Entra ID claims mapping policies).
- Enables cross-domain trust without replicating identities.

**Zero Trust / Continuous Access Evaluation (CAE)**
- "Never trust, always verify" — authenticate and authorize on every request with full context.
- CAE enables near-real-time revocation: resource servers (Exchange, SharePoint) are notified of token lifetime events (user disabled, password change, session revoked).
- Signals: device compliance, location, user risk, sign-in risk feed into access decisions.

**Least Privilege / Just-In-Time (JIT) Access**
- Grant minimum permissions required; elevate only when needed and for a bounded time.
- Privileged Identity Management (PIM) implements JIT for Azure and Entra roles.
- Access Reviews enforce periodic re-attestation of group and role membership.

---

## 2. Network Configuration for Identity and Privileges Management

### 2.1 AD FS Network Topology

```
Internet
    │
    ▼
[WAP — Web Application Proxy]   ← DMZ
    │  (HTTPS 443 inbound)
    │  Reverse proxy; terminates TLS; forwards to AD FS farm
    │
    ▼  (HTTP/HTTPS internally, port 443 or 49443 for device auth)
[AD FS Servers]                 ← Corporate network
    │
    ▼
[Active Directory Domain Controllers]
```

- **WAP (Web Application Proxy)**: Windows Server role in DMZ; publishes AD FS endpoints externally.  
  No direct internet access to AD FS servers; WAP acts as the only externally reachable node.
- **AD FS Farm**: Two or more servers behind an internal load balancer (ILB); shared configuration database (WID or SQL).
- **Firewall Rules**:
  - Internet → WAP: TCP 443
  - WAP → AD FS: TCP 443, TCP 49443 (device registration)
  - AD FS → DC: TCP/UDP 389 (LDAP), TCP 636 (LDAPS), TCP 88 (Kerberos), TCP/UDP 53 (DNS)
  - AD FS → Azure AD: TCP 443 outbound to `login.microsoftonline.com`
- **SSL/TLS Certificates**:
  - Service communications certificate (presented to clients at `adfs.contoso.com`).
  - Token signing certificate (signs SAML assertions and OIDC tokens).
  - Token decryption certificate (optional; decrypts encrypted SAML assertions from SPs).
  - Certificates must be renewed before expiry; AD FS supports auto-rollover for token certs.
- **Extranet Lockout**: AD FS Smart Lockout tracks bad password attempts per-user from extranet; does not lock intranet. Configure `ExtranetLockoutEnabled`, `ExtranetObservationWindow`, `ExtranetLockoutThreshold`.

---

### 2.2 Pass-Through Authentication (PTA) Network Requirements

- PTA Agent installed on on-premises servers (not DCs) establishes outbound-only persistent HTTPS connections to Azure Service Bus endpoints.
- No inbound firewall ports required — all traffic is outbound TCP 443.
- Agents validate passwords against on-premises AD; password never stored in Azure.
- Minimum 3 agents recommended for HA; agents register with Entra ID via token.
- Required outbound URLs: `*.msappproxy.net`, `*.servicebus.windows.net`, `login.microsoftonline.com`.

---

### 2.3 Application Proxy Connector Network Requirements

- Connector is installed on-premises; communicates outbound-only over HTTPS (TCP 443) to Azure.
- No inbound rules, no DMZ, no firewall holes — connector initiates all connections to Azure Connector Service.
- Connector → Back-end app: HTTP or HTTPS (port depends on app); Kerberos Constrained Delegation (KCD) for Windows Integrated Authentication.
- Connector groups allow affinity between connectors and published apps (e.g., per-region, per-network segment).
- TLS 1.2 minimum required between connector and Azure; certificates validated using system trust store.
- Proxy support: connectors can route through a forward HTTP proxy if needed (configure `ProxyAddress` in connector service config).

---

### 2.4 Azure AD Connect / Entra Connect Network Requirements

- Entra Connect server requires outbound TCP 443 to Azure AD, and inbound/outbound to on-premises AD DS (LDAP 389, LDAPS 636, Kerberos 88, RPC).
- Password Hash Sync (PHS): MD4 hash of the MD4 hash transmitted to Azure AD over TLS.
- Staging mode server replicates changes but does not write to Azure AD — used for DR and testing.
- Password Writeback: Entra Connect establishes outbound TLS connection to Azure Service Bus; password reset events are pushed down to on-premises AD.

---

### 2.5 NPS Extension for MFA (RADIUS Integration)

- Azure MFA NPS Extension intercepts RADIUS Access-Request, performs MFA challenge via Azure MFA service, then passes/rejects to NPS.
- Requires outbound HTTPS (TCP 443) from NPS server to Azure MFA cloud endpoints.
- Supports VPN gateways, RD Gateway, and any RADIUS-compatible network infrastructure.
- Communication is mutual TLS; NPS Extension registers a certificate in the tenant during setup.
- Network policy must forward authentication to the extension; extension communicates result back via Access-Accept or Access-Reject.

---

### 2.6 Hybrid Identity Network Patterns Summary

| Method | Inbound Ports Required | Password Leaves On-Prem? | HA Mechanism |
|---|---|---|---|
| Password Hash Sync (PHS) | None (outbound only) | Hash only | Multiple Entra Connect (staging) |
| Pass-Through Auth (PTA) | None (outbound only) | No | Multiple PTA Agents |
| Federation (AD FS) | 443 on WAP (from internet) | No | AD FS Farm + WAP Farm |
| Application Proxy | None (outbound only) | N/A | Connector Groups |

---

### 2.7 DNS and Certificate Considerations

- Federation Service Name (e.g., `adfs.contoso.com`) must resolve publicly to WAP and internally to AD FS ILB.
- Split-brain DNS ensures internal clients resolve to the internal AD FS endpoint; external clients to WAP.
- Wildcard or SAN certificates for AD FS must cover the federation service name and DRS endpoint.
- Certificate pinning is not recommended for federation endpoints — breaks key rotation.
- Entra ID relies on publicly trusted CAs for all service endpoints; self-signed certificates are not supported for cloud-facing services.

---

## 3. Azure / Microsoft Entra Implementation and Security Considerations

### 3.1 Microsoft Entra ID Overview

Microsoft Entra ID (formerly Azure AD) is Microsoft's cloud-based identity platform supporting OAuth 2.0, OIDC, SAML 2.0, and WS-Federation. It serves as both an IdP and an authorization server.

**Key services:**
- **Authentication**: Sign-in with password, MFA, passwordless, external identity providers.
- **Authorization**: App roles, OAuth scopes, Conditional Access, PIM.
- **Federation**: Integration with on-premises AD DS via Entra Connect, and with third-party IdPs via SAML/OIDC federation.
- **Governance**: Access Reviews, Entitlement Management, PIM.

---

### 3.2 App Registration and Service Principals

- **App Registration**: Defines the application's identity in the home tenant — client ID, redirect URIs, API permissions, app roles, certificates/secrets.
- **Service Principal**: The instantiation of an App Registration in a specific tenant; holds the actual role assignments and consent grants.
- **Federated Credentials** (Workload Identity Federation): Replace client secrets with tokens from external IdPs (GitHub Actions, Kubernetes, AWS) — eliminates long-lived secrets.
- **Certificate-based authentication** is preferred over client secrets for confidential clients (certificates are asymmetric; secrets are symmetric shared keys with expiry risks).
- Secrets and certificates have configurable expiry — enforce short lifetimes via policy and implement rotation automation.
- `appRoles` defined in the manifest are included in the `roles` claim of access tokens.
- Admin Consent vs. User Consent: delegated permissions with sensitive scopes require admin consent; tenant-wide admin consent propagates to all users.
- Application Consent Workflow allows users to request admin consent when blocked — logs and approves requests.

---

### 3.3 Multi-Factor Authentication (MFA)

**Authentication Methods:**
| Method | Strength | Phishing-Resistant |
|---|---|---|
| FIDO2 / Passkey | Very High | Yes |
| Certificate-Based Auth (CBA) | Very High | Yes |
| Microsoft Authenticator (Passwordless Phone Sign-in) | High | Yes |
| OATH Hardware Token (TOTP) | High | No |
| OATH Software Token (Authenticator App TOTP) | Medium-High | No |
| SMS / Voice OTP | Medium (SIM-swap risk) | No |
| Email OTP | Medium | No |

- **Authentication Strengths** policy: define ordered lists of acceptable authentication method combinations for Conditional Access.
- **Security Defaults**: Microsoft-managed baseline enabling MFA for all users and blocking legacy auth — replaces per-user MFA (deprecated).
- **MFA Registration**: Combined registration (`/mysecurityinfo`) for SSPR and MFA methods; registration campaign nudges users to register.
- **MFA Server (deprecated)**: On-premises MFA Server reached end of support — migrate to cloud MFA.
- **NPS Extension**: Integrates cloud MFA into RADIUS-based flows (VPN, RD Gateway); issues an Access-Accept/Access-Reject based on MFA outcome.

---

### 3.4 Conditional Access

Conditional Access is the policy engine that acts as the Zero Trust control plane for Entra ID.

**Signal → Decision → Enforcement:**
```
Signals:              Decision:        Enforcement:
User/Group/Role  ──►  Grant / Block    Require MFA
Application      ──►  Allow            Require Compliant Device
Location         ──►  Allow w/ Ctrl    Require Hybrid Join
Device State     ──►                  Require Auth Strength
Sign-in Risk     ──►                  Session Controls (app enforced, MCAS, token lifetime)
User Risk        ──►
```

**Key Policy Controls:**
- **Grant Controls**: Require MFA, require compliant device, require hybrid Azure AD join, require approved app, require authentication strength, require Terms of Use.
- **Block**: Explicitly deny access based on any combination of signals.
- **Session Controls**: Sign-in frequency, persistent browser session, app-enforced restrictions (SharePoint/Exchange), Conditional Access App Control (MCAS proxy).
- **Named Locations**: IP ranges (IPv4/IPv6) and countries; used for location-based conditions.
- **Device Filters**: Target or exclude specific devices using device attributes (trustType, isCompliant, model, manufacturer, extensionAttribute).
- **Microsoft-Managed Policies**: Baseline policies managed by Microsoft; tenant admin can enable/disable/extend.
- **What-If tool**: Simulates policy evaluation for a given user/app/IP/device combination — essential for troubleshooting.
- **Report-Only mode**: Deploy policy without enforcement; audit log shows what would have been applied.

**Security Considerations:**
- Always have an emergency access (break-glass) account excluded from CA policies.
- Avoid blanket exclusions of service accounts — use workload identity Conditional Access instead.
- Device compliance signals come from Intune; devices must be enrolled and compliant.
- Avoid relying solely on IP-based Named Locations — use device compliance and authentication strength for stronger guarantees.

---

### 3.5 Identity Protection

Entra ID Identity Protection uses ML models to detect risky sign-ins and risky users.

**Risk Types:**
- **Sign-in risk**: Probability that the sign-in was not performed by the legitimate user (anonymous IP, atypical travel, malware-linked IP, unfamiliar sign-in properties, leaked credentials, token anomaly).
- **User risk**: Probability that the account is compromised (leaked credentials, threat intelligence).

**Risk Levels:** Low, Medium, High.

**Risk Policies (configured via Conditional Access):**
- Sign-in risk policy → Require MFA when sign-in risk ≥ Medium.
- User risk policy → Require password change when user risk ≥ High.
- MFA registration policy → Require registration for all users.

**Investigation:**
- Risky Users report: shows confirmed compromised, dismissed, and at-risk users.
- Risky Sign-ins report: shows individual sign-in events with risk details and detection types.
- Risk detections report: granular detail per detection event.
- Admin can confirm compromise (elevates risk, triggers CAE revocation) or dismiss false positives.

**Workload Identity Risk:**
- Service principals and managed identities can also be flagged for anomalous credential usage.
- Workload ID Identity Protection policies can block risky service principals.

---

### 3.6 Privileged Identity Management (PIM)

- JIT activation of Azure roles and Entra ID roles: eligible assignments require explicit activation with optional justification and MFA.
- Time-bound active assignments enforce least privilege by default.
- **Activation controls**: require MFA, require justification, require approval (multi-level), require ticket number.
- **Assignment types**: Eligible (can activate), Active (always active), permanent active (legacy — avoid).
- **Access Reviews** for PIM: periodic certification of who holds eligible or active role assignments.
- PIM for Groups: manage group membership (owner/member) with JIT semantics — used to gate group-based access (app roles, shared mailboxes, etc.).
- **Alerts**: PIM generates alerts for standing admin accounts, roles assigned outside PIM, duplicate role assignments.
- Audit log: full history of activations, assignments, deactivations, and reviews.

---

### 3.7 AD FS Integration and Migration to Entra ID

**AD FS Use Cases Remaining:**
- Applications requiring claims rules that cannot be replicated in Entra ID claims mapping policies.
- Smart card / certificate authentication with on-premises PKI.
- On-premises only applications (no cloud path).
- Complex WS-Trust active scenarios.

**Migration Path (AD FS → Entra ID):**
1. Inventory apps using AD FS using the AD FS activity report in Entra ID.
2. Classify: Ready to migrate / Needs investigation / Not migratable.
3. For SAML apps: configure Entra ID Enterprise Application, migrate claims configuration.
4. Test in parallel before cutting over.
5. Convert `ImmutableId` / federation domain once all apps are migrated.

**SSL / Token Signing Certificates:**
- Token signing certificate rolled by AD FS automatically (default 1-year, auto-renew 20 days before expiry).
- Azure AD must be updated when token signing cert rolls — Entra Connect handles this via AutoCertRollover if enabled.
- SSL certificate (service communications) is not auto-renewed; must be manually replaced before expiry.

**Claims Issuance Policies:**
- Claim rules written in AD FS Claims Rule Language: `c:[Type == "...", Value == "..."] => issue(Type = "...", Value = c.Value);`
- Entra ID equivalent: Claims Mapping Policy (JSON), applied to service principals via Graph API or PowerShell.
- Entra ID supports transforming, filtering, and emitting directory attributes as SAML/JWT claims.


┌─────────────────────────────────────────────────────────────────────────┐
│                         CORPORATE NETWORK                               │
│                                                                         │
│  ┌──────────────────────────┐    ┌──────────────────────────────────┐  │
│  │     AD DS (on-prem)      │    │    AD FS (on-prem)               │  │
│  │  ─────────────────────   │    │  ──────────────────────────────  │  │
│  │  - User accounts         │    │  - Federation / SSO to cloud     │  │
│  │  - Computer accounts     │    │  - Issues SAML/OIDC tokens       │  │
│  │  - Kerberos KDC          │    │  - Claims issuance rules         │  │
│  │  - Group Policy          │    │  - Talks to Entra ID via         │  │
│  │  - NTDS.dit              │    │    WS-Federation trust           │  │
│  └────────────┬─────────────┘    └──────────────┬───────────────────┘  │
│               │                                  │                      │
│               │ Kerberos (port 88)               │ HTTPS 443            │
│               │ LDAP (port 389)                  │                      │
│               │                                  │                      │
│  ┌────────────▼──────────────────────────────────▼───────────────────┐ │
│  │                    DEVICE IDENTITY TYPES                          │ │
│  │                                                                   │ │
│  │  ┌─────────────────┐  ┌──────────────────┐  ┌─────────────────┐  │ │
│  │  │  Domain-Joined  │  │  Hybrid Joined   │  │  Entra Joined   │  │ │
│  │  │  (on-prem only) │  │  (both worlds)   │  │  (cloud only)   │  │ │
│  │  │  ─────────────  │  │  ──────────────  │  │  ─────────────  │  │ │
│  │  │ AD computer     │  │ AD computer acct │  │ Entra device    │  │ │
│  │  │ account only    │  │ + Entra device   │  │ object only     │  │ │
│  │  │                 │  │                  │  │                 │  │ │
│  │  │ Auth: Kerberos  │  │ Auth: Kerberos   │  │ Auth: PRT       │  │ │
│  │  │        + NTLM   │  │         + PRT    │  │                 │  │ │
│  │  │                 │  │                  │  │                 │  │ │
│  │  │ SSO: TGT via    │  │ SSO: TGT for     │  │ SSO: PRT for    │  │ │
│  │  │ Kerberos only   │  │ on-prem apps     │  │ cloud apps only │  │ │
│  │  │                 │  │ PRT for cloud    │  │                 │  │ │
│  │  │ Needs DC        │  │                  │  │ No DC needed    │  │ │
│  │  │ line-of-sight   │  │ Needs DC for     │  │                 │  │ │
│  │  │                 │  │ on-prem auth     │  │                 │  │ │
│  │  │ IWA: Yes        │  │ IWA: Yes         │  │ IWA: Yes        │  │ │
│  │  │                 │  │                  │  │ (via Seamless   │  │ │
│  │  │                 │  │                  │  │  SSO bridge)    │  │ │
│  │  └────────┬────────┘  └────────┬─────────┘  └────────┬────────┘  │ │
│  └───────────┼────────────────────┼─────────────────────┼───────────┘ │
└──────────────┼────────────────────┼─────────────────────┼─────────────┘
               │                    │                     │
               │         Entra Connect syncs              │
               │         AD DS → Entra ID                 │
               │         (users + devices)                │
               ▼                    ▼                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        ENTRA ID (cloud)                                 │
│                                                                         │
│   User objects ◄──── synced from AD DS (or cloud-only)                 │
│   Device objects ◄── synced from AD DS (Hybrid) or direct (Entra Join) │
│   PRT issuance ────► WAM (Web Account Manager) on device               │
│   Seamless SSO ────► AZUREADSSOACC computer account in AD DS           │
│                       (bridges Entra Join → Kerberos for on-prem apps) │
│                                                                         │
│   AD FS federation ► used when org hasn't migrated to Entra ID auth    │
│                       AD FS acts as IdP, Entra ID trusts it             │
└─────────────────────────────────────────────────────────────────────────┘

AD DS  = the directory (stores identities, issues Kerberos)
AD FS  = the federation service (issues tokens to cloud/external apps)
Entra  = the cloud directory + token issuer (replaces AD FS for cloud)

Migration direction:  Domain-Joined → Hybrid Joined → Entra Joined
                      AD FS         → Entra ID native auth

---

### 3.8 Seamless SSO (Kerberos-based)

- Entra ID Seamless SSO works with PHS and PTA (not Federation — federation uses AD FS for SSO).
- Entra Connect creates a computer account `AZUREADSSOACC` in on-premises AD; its Kerberos decryption key is shared with Azure AD.
- Domain-joined clients get a Kerberos service ticket for `AZUREADSSOACC`, which Azure AD validates without a password prompt.
- Requires browsers to be in the Intranet zone (IE/Edge) or explicitly configured (Chrome via group policy) to pass Kerberos tickets.
- Users must be in scope of Entra Connect sync; seamless SSO token is then exchanged for Entra ID session.

---

### 3.9 Microsoft Graph and API Authorization

- Microsoft Graph uses OAuth 2.0 with Entra ID as the authorization server; access tokens carry scopes and claims.
- **Permission types**:
  - *Delegated*: User + App; `scp` claim in token; requires signed-in user context.
  - *Application*: App-only; `roles` claim in token; no user context — use with caution, grant least privilege.
- **Resource-Specific Consent (RSC)**: Teams/SharePoint model granting app access to a specific team/site instead of tenant-wide; reduces blast radius.
- **Admin Consent** required for: `User.Read.All`, `Mail.Read`, `Directory.ReadWrite.All`, and other high-privilege scopes.
- **Incremental / Dynamic Consent**: Request only necessary scopes at login; request additional scopes just-in-time.
- Legacy Azure AD Graph API (graph.windows.net) is retired — migrate to Microsoft Graph (graph.microsoft.com).
- MSAL (Microsoft Authentication Library) replaces ADAL; handles token acquisition, caching, and silent renewal across platforms.

---

### 3.10 Workload Identity / Managed Identity

- **Managed Identity**: Azure-managed service principal; credentials rotated automatically by Azure platform.
  - *System-assigned*: Tied to resource lifecycle; deleted when resource is deleted.
  - *User-assigned*: Standalone resource; shareable across multiple Azure resources.
- Eliminates need for application credentials in code or configuration — preferred over client secrets.
- Assign Azure RBAC roles to managed identity at narrowest scope (resource > resource group > subscription).
- **Federated Identity Credentials** (Workload Identity Federation): External tokens (GitHub OIDC, Kubernetes service account tokens) exchanged for Entra ID tokens — eliminates long-lived secrets in CI/CD pipelines.

---

### 3.11 B2C / External Identity

- Azure AD B2C / Entra External ID: separate tenants for customer-facing applications; policies (user flows) define authentication experience.
- Supports social IdP federation (Google, Facebook, Apple) and enterprise federation (SAML/OIDC).
- Tokens acquired from B2C use tenant-specific endpoint (`{tenant}.b2clogin.com`).
- MSAL for B2C must target B2C authority; token acquisition follows the same MSAL patterns but with custom policy parameter.
- Access tokens for downstream APIs are configured via API scopes defined in the B2C app registration.

---

### 3.12 Azure RBAC and Entra ID Roles

- **Entra ID roles** (directory roles): control administration of directory resources (User Administrator, Global Administrator, Application Administrator).
- **Azure RBAC roles**: control access to Azure resource plane (Owner, Contributor, Reader, plus hundreds of built-in and custom roles).
- **Separation of concerns**: Entra ID roles ≠ Azure RBAC roles — a Global Administrator does not automatically have Contributor on Azure subscriptions (unless elevated via PIM).
- **Custom roles**: Define fine-grained permission sets for both Azure (JSON `Actions`/`NotActions`/`DataActions`) and Entra ID (directory permission subsets).
- **ABAC conditions** on Azure RBAC: constrain role assignments with attribute-based conditions (e.g., blob index tags, storage path patterns).

---

### 3.13 Device Identity

- **Azure AD Registered**: Personal (BYOD) devices; device identity created in Entra ID; used for Workplace Join.
- **Azure AD Joined**: Cloud-only join; device identity in Entra ID; enables SSO to cloud resources via PRT (Primary Refresh Token).
- **Hybrid Azure AD Joined**: Device identity exists in both on-premises AD and Entra ID via Entra Connect device writeback; required for Kerberos-based on-premises SSO from modern devices.
- **Primary Refresh Token (PRT)**: Long-lived device-bound token that enables SSO across all apps on the device; protected by device TPM where available.
- Devices in "pending" state: Hybrid join sync not yet complete; verify Entra Connect sync scope and `userCertificate` attribute.
- Intune enrollment + compliance policy enables device-based Conditional Access grant controls.

---

### 3.14 Security Considerations Summary

| Area | Key Risk | Mitigation |
|---|---|---|
| Admin accounts | Compromise = full tenant control | PIM, phishing-resistant MFA, break-glass accounts, no email on admin account |
| Client secrets | Long-lived, can be exfiltrated | Use certificates or federated credentials; enforce short expiry; rotate via automation |
| Legacy auth protocols | Block MFA, enable credential spray | Block legacy auth via Conditional Access; disable SMTP AUTH, Basic Auth |
| Consent grants | Malicious app phishing | Restrict user consent; require admin consent for sensitive scopes; audit delegated permissions |
| Token theft | Lateral movement via stolen tokens | CAE, token binding, short access token lifetime, compliant device requirement |
| Overprivileged roles | Blast radius of compromise | Least privilege, ABAC conditions, PIM, Access Reviews |
| Federated cert expiry | Authentication outage | Monitor cert expiry; automate rotation alerts; maintain AD FS auto-rollover |
| Password spray | Bulk account compromise | Smart Lockout, password protection (banned passwords), Identity Protection risk policies |
| Hybrid identity | On-prem compromise → cloud | Protect Entra Connect server; restrict AD to Entra ID sync scope; isolate AD FS servers |

---

## 4. 100 Tech Points from sap.csv

Each point is derived from or directly maps to a path in the SAP support case taxonomy.

### Authentication Methods and MFA

1. **MFA deployment planning**: Assess authentication method registration, licensing requirements, and rollout scope before enabling Conditional Access MFA enforcement.
2. **Authenticator App (TOTP mode)**: Time-based OTP generated in Microsoft Authenticator; requires device clock sync; serves as fallback to passwordless phone sign-in.
3. **Authenticator App (Passwordless phone sign-in)**: Number matching and additional context (app name, location) must be enabled to mitigate MFA fatigue attacks.
4. **Hardware OATH token provisioning**: Tokens are imported via CSV (serial number, secret key, time step) and assigned to users; require TOTP-compatible 30-second step size.
5. **Phone and SMS authentication**: Considered weaker (SIM-swap, SS7 vulnerabilities); Microsoft recommends migrating users to Authenticator App or FIDO2.
6. **External authentication methods**: Entra ID supports plugging in third-party MFA providers (e.g., Duo) via External Authentication Methods (EAM) API — replaces older custom controls.
7. **Security Defaults**: Tenant-wide baseline enforcing MFA for all users, protecting privileged roles, and blocking legacy auth; mutually exclusive with named Conditional Access policies.
8. **MFA Registration campaign**: Entra ID can nudge users to register during sign-in; configurable snooze duration and registration deadline.
9. **MFA registration portal** (`/mysecurityinfo`): Combined registration for MFA and SSPR; users manage their authentication methods here.
10. **Unexpected MFA prompt root cause**: Caused by new device, new location, token expiry, sign-in risk elevation, or session control sign-in frequency policy enforcement.
11. **MFA prompt on NPS extension failure**: NPS extension timeout or connectivity issue to Azure MFA cloud service causes Access-Reject — check NPS extension logs and outbound 443 connectivity.
12. **Unable to sign in due to MFA**: Can result from user having no registered methods, blocked phone number, or policy requiring stronger auth than user has registered.
13. **MFA usage reports and logs**: Sign-in logs in Entra ID show authentication method used and MFA result; exportable via Log Analytics, Event Hub, or Storage Account.
14. **MFA plan and manage deployment**: Staged rollout: enable per-user → group-based Conditional Access → monitor with sign-in logs and MFA report → enforce globally.
15. **FIDO2 security key troubleshooting**: Issues include missing FIDO2 attestation in tenant allow-list, browser compatibility (requires CTAP2), or USB/NFC hardware driver issues.

### Passkeys and Passwordless

16. **Passkey (FIDO2) provisioning in Entra ID**: Enabled per-user via Authentication Methods policy; requires user to register key at `mysecurityinfo`; authenticator must meet attestation requirements if enforce attestation is enabled.
17. **Passwordless phone sign-in prerequisites**: User must have Authenticator app with account added, have the account in scope for passwordless policy, and device must be Intune-registered or compliant in some configurations.
18. **Passwordless authentication strength**: Define Authentication Strength requiring FIDO2 or certificate-based auth for privileged operations; enforce via Conditional Access grant control.

### Conditional Access

19. **Grant vs. Block controls**: Grant controls are AND/OR composable; Block is a hard denial that overrides Grant; Block should be scoped narrowly to avoid locking out legitimate users.
20. **Assigning users and apps to CA policies**: Target specific groups and applications; use Include/Exclude carefully; "All users" + "All cloud apps" is a powerful but risky scope — always exclude break-glass accounts.
21. **Session controls — sign-in frequency**: Forces re-authentication after a configured interval; use per-app for sensitive applications; avoid very short intervals on all apps (poor UX).
22. **Session controls — persistent browser session**: Controls whether "Stay signed in?" is offered; should be disabled on shared/kiosk devices.
23. **Session controls — App-enforced restrictions**: Works with Exchange Online and SharePoint Online to enforce limited access (view-only, no download) from unmanaged devices.
24. **Session controls — MCAS / Defender for Cloud Apps proxy**: Routes sessions through MCAS reverse proxy; enables session-level DLP, file download blocking, and activity monitoring.
25. **Configuring new CA policy settings**: Use named locations, device filters, authentication context to build precise policies; always test with What-If before enabling.
26. **Report-only mode**: Allows safe policy testing; results appear in sign-in logs under "Report-only: Would not apply" / "Would apply"; does not affect real access.
27. **Troubleshooting resultant set of policy**: Use CA What-If tool; check sign-in log → Conditional Access tab for per-policy evaluation result and failure reason.
28. **Troubleshooting device state in CA**: Devices must be Entra ID joined/registered and compliant (Intune); check device object status, compliance policy assignment, and PRT issuance.
29. **Microsoft-managed CA policies**: Baseline policies (e.g., require MFA for admins, block legacy auth) deployed and managed by Microsoft; tenant admin can extend or disable.
30. **CA for workload identities**: Separate Conditional Access policies for service principals; conditions include IP-based named locations and risk level; block or require compliant behavior.

### AD FS

31. **Initial AD FS configuration with Azure AD**: Requires running `Convert-MsolDomainToFederated` (legacy) or Entra Connect federation configuration; creates relying party trust in AD FS and domain federation in Entra ID.
32. **AD FS deployment and upgrade**: Plan for server sizing (WAP + AD FS farm), SQL vs. WID database, load balancer health probes, and TLS certificate staging before cutover.
33. **AD FS Smart Lockout vs. Extranet Lockout**: Smart Lockout is on by default for cloud auth; AD FS Extranet Lockout specifically protects on-premises accounts from extranet password spray without locking intranet authentication.
34. **AD FS extranet authentication failures**: WAP proxy trust to AD FS must be valid; check WAP-to-AD-FS connectivity and `preauthentication` type (Passthrough vs. AD FS).
35. **SSL certificate on AD FS**: Bound to `ADFS/SSL` on the AD FS service and to the HTTPS binding on WAP; must be replaced on all farm members and WAPs before expiry; use `Set-AdfsSslCertificate` and `Set-WebApplicationProxySslCertificate`.
36. **Token signing certificate**: Must match what Azure AD expects; auto-rollover via `AutoCertificateRollover = $true`; after rollover, Entra Connect or manual federation metadata update must sync the new cert to Azure AD.
37. **Token decryption certificate**: Service providers encrypt assertions using the IdP's published decryption cert; must be updated on all relying parties before rotation.
38. **Claims issuance policies**: Rules control which attributes are emitted as claims; use `c:[]` selector and `=> issue(...)` or `=> add(...)` statements; support attribute store lookups (AD, SQL, custom).
39. **Claims rules for SAML apps migration**: Map AD attributes to SAML claims (NameID, groups, email) in AD FS; replicate equivalent claims mapping policy in Entra ID before cutover.
40. **AD FS SAML app migration to Entra ID**: Use Entra ID ADFS Migration tool to generate migration report; test parallel authentication with ADFS activity report; cut over by re-pointing SP metadata.
41. **Problem with authentication to previously functioning apps**: Check relying party trust certificate expiry, claims rule changes, and Windows Event Log (AD FS admin log, security log) on AD FS servers.
42. **AD FS on Windows Server 2016/2019/2022**: Feature level differences — Server 2019 introduces `PrimaryRefreshToken` support, `ExtranetSoftLockout`; Server 2022 adds passwordless support and improved logging.
43. **ADFS in Azure AD Connect**: AADConnect can configure and manage AD FS federation; wizard handles relying party trust, domain federation, and token signing cert updates.

### Password and Hybrid Auth

44. **Password Hash Sync (PHS) enablement**: Entra Connect synchronizes NTLM hash of hash every 2 minutes; enabling PHS does not automatically change sign-in method — domain must be converted from federated if switching from AD FS.
45. **On-premises Azure AD Password Protection**: Banned password list (global + custom) enforced by DC Agent on every password change/reset in on-premises AD; requires proxy service for policy download from Azure.
46. **SSPR (Self-Service Password Reset) with writeback**: Requires Password Writeback enabled in Entra Connect; user resets password in cloud → writeback to on-premises AD via Service Bus channel.
47. **Configuring ADFS in AAD Connect**: Wizard in Entra Connect allows configuring existing AD FS farm or deploying new one; handles trust, certificate, and federation domain configuration.
48. **PTA agent registration**: Agents must be registered with Entra ID using Global Administrator credentials; use `Register-AzureADConnectAuthenticationAgent` cmdlet; monitor agent status in Entra admin center.
49. **Seamless SSO deployment with PTA or PHS**: Enable in Entra Connect; creates `AZUREADSSOACC` computer account; roll out via Group Policy to add `autologon.microsoftonline.com` to the Intranet zone.
50. **Seamless SSO troubleshooting**: Verify `AZUREADSSOACC` account exists and Kerberos key is not expired (re-roll annually); check browser zone settings; use Fiddler/network trace to confirm Kerberos ticket in request.

### App Registration and Development

51. **Creating new App registration**: Choose single-tenant vs. multi-tenant; set redirect URIs (must be HTTPS except localhost); select supported account types matching audience.
52. **Managing API permissions and Admin Consent**: Add permission → Select API → Select delegated or application scope → Grant admin consent; admin consent can be pre-granted for all users to avoid per-user consent prompt.
53. **Certificates and secrets management**: Secrets expire; certificates are more secure (asymmetric key pair); Federated credentials are most secure (no stored secret); monitor expiry with Entra ID notifications and Azure Monitor.
54. **Federated credentials for GitHub Actions**: Configure subject claim matching `repo:org/repo:ref:refs/heads/main`; exchange OIDC token from GitHub for Entra ID access token — no secret stored in GitHub.
55. **Acquiring tokens with MSAL**: Use `AcquireTokenSilent` → `AcquireTokenInteractive` (or `AcquireTokenByClientCredential` for daemons); MSAL handles token cache, silent renewal, and `claims_challenge` responses.
56. **Migrating from ADAL to MSAL**: ADAL is deprecated; MSAL supports modern auth flows, CAE, Continuous Access Evaluation; migration involves updating authority URL format and flow configuration.
57. **Acquiring tokens for B2C tenant**: B2C authority: `https://{tenant}.b2clogin.com/{tenant}.onmicrosoft.com/{policy}`; token endpoint differs from standard Entra ID; MSAL requires authority override.
58. **App registration scope and audience**: `aud` claim in token must match the registered Application ID URI; multi-tenant apps must validate `iss` against per-tenant issuer URL.

### Enterprise Applications

59. **SSO configuration — SAML**: Configure Entity ID, Reply URL (ACS URL), SAML claims (NameID format, attribute mappings); download federation metadata XML for SP configuration.
60. **SSO configuration — OIDC**: Register app in Entra ID; set redirect URI; configure scopes; app uses standard OIDC flow with Entra ID as IdP.
61. **Access management for enterprise apps**: Assign users, groups, and app roles; enable self-service app assignment for users to request access (requires approval workflow).
62. **Activity logs for enterprise apps**: Sign-in logs filterable by application; audit logs record consent grants, role assignments, policy changes; retention 30 days (P1/P2), extendable via Log Analytics.
63. **ADFS to Entra ID SAML app migration (enterprise apps)**: Import SP metadata → configure claims → test with parallel sign-in → cut DNS/metadata to point to Entra ID.
64. **Managing admin and user consent**: Configure consent policies in Entra ID — allow/block user consent, require admin consent for all delegated permissions, configure admin consent workflow for user requests.
65. **Admin Consent Workflow**: Users blocked by consent policies can send requests to admins; admins receive email notification and approve/deny in Entra admin center with full context of permission request.

### Application Proxy

66. **Application Proxy connector configuration**: Install connector on domain member server; authenticate during install; connector registers with Azure AD Application Proxy service; verify outbound connectivity to `*.msappproxy.net`.
67. **Connector groups**: Group connectors by network proximity to back-end apps; assign apps to connector groups; distribute load across connectors in a group.
68. **Application Proxy — pre-authentication**: Passthrough (no pre-auth) vs. Azure AD (requires valid Entra session before traffic forwarded) — use Azure AD pre-auth for published internal apps.
69. **Kerberos Constrained Delegation (KCD) for App Proxy**: Connector impersonates user to back-end app using KCD; requires SPN configuration on back-end app's service account, and delegation trust on connector machine account.

### Microsoft Graph and API Authorization

70. **Microsoft Graph access token acquisition**: Use client credentials flow for background services; authorization code + PKCE for user-delegated access; token endpoint: `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token`.
71. **Graph connection failures**: Check `access_token` audience (`aud=https://graph.microsoft.com`); verify tenant endpoint vs. common endpoint; check conditional access blocking service principal sign-in.
72. **Graph access denied — Resource Specific Consent**: RSC permissions granted at Teams/site level via Graph API; differ from tenant-wide permissions; check both RSC grant and tenant-wide permission for correct API path.
73. **Graph access denied — permission issues**: Verify application has required permission in app registration AND admin consent has been granted; distinguish between delegated (needs user in scope) and application (service-to-service).
74. **AAD Graph to MS Graph migration**: Azure AD Graph is retired; all `graph.windows.net` calls must move to `graph.microsoft.com`; audit all SDK versions and direct HTTP calls; update MSAL authority URL.
75. **Microsoft Graph Users and Groups API**: `GET /users`, `GET /groups`, `GET /groups/{id}/members`; require `User.Read.All` or `Group.Read.All` (application) or equivalent delegated scopes.

### Devices and Hybrid Join

76. **Azure AD Registered device configuration**: Targets BYOD; users register personal device in Settings → Accounts → Access work or school; device gets device certificate enabling Entra ID app SSO.
77. **Hybrid Azure AD Join configuration**: Entra Connect device sync must be enabled; GPO or Intune policy triggers device registration on domain-joined Windows clients; `dsregcmd /status` verifies join state.
78. **Devices in pending state**: Device object in Entra ID shows "Pending" when `userCertificate` attribute not yet synced from AD; check Entra Connect sync rules, attribute flow, and Connector filter.
79. **Azure AD Join access issues**: PRT not issued if device is not compliant or sign-in failed; `dsregcmd /status` shows PRT state, SSO state, and error codes; common cause: Conditional Access blocking sign-in during join.
80. **VM extension — Azure AD Login (Windows)**: Enables sign-in to Azure Windows VMs using Entra ID credentials; requires AADLoginForWindows extension, RBAC role assignment (Virtual Machine User Login / Administrator Login), and line-of-sight or hybrid connectivity.
81. **VM extension — Azure AD Login (Linux)**: AADSSHLoginForLinux extension enables SSH with Entra ID credentials using `az ssh vm`; similar RBAC requirements as Windows login extension.

### Governance and Compliance

82. **Security reports — Risky Users and Risky Sign-ins**: Accessible in Entra admin center under Identity Protection; filterable by risk level, detection type, date; requires Entra ID P2 for full detail.
83. **Risk investigation workflow**: Investigate risk detections → confirm/dismiss → remediation (force password change, block user, revoke sessions via `revokeSignInSessions` Graph API).
84. **Access Reviews for group membership**: Periodic review assigned to resource owners or managers; auto-remediation on denial (remove user, remove access); integrated with PIM for role reviews.
85. **Entitlement Management (access packages)**: Define bundles of resources (groups, apps, SharePoint sites) as access packages; configure approval workflow, access duration, and recertification cadence.

### Workload Identity

86. **Workload Identity — Issues with Identity Protection**: Service principals flagged at high risk can be blocked by Workload ID Conditional Access policy; investigate anomalous sign-in patterns in Identity Protection reports.
87. **Managed Identity vs. Service Principal**: Prefer managed identity for Azure resources (auto-rotated credentials, no secret management); use service principal only when managed identity is not supported.
88. **Workload Identity Federation**: Eliminates secrets for GitHub Actions, GitLab CI, AKS workloads; configure issuer, subject, and audience in Entra federated credential; token exchange via STS token endpoint.

### B2C / External Identities

89. **B2C tenant and MS Graph API**: B2C tenants have different Graph endpoints and permission model; use `User.ReadWrite.All` and `Directory.ReadWrite.All` with application permission for B2C user management via Graph.
90. **B2C user flows and custom policies**: User flows handle standard scenarios (sign-up/sign-in, password reset); custom policies (Identity Experience Framework) allow complex claims transformation, external API calls, and step-up MFA.
91. **B2C token customization**: Claims can be added via REST API technical profile calls during user journey; access token lifetime and issuer configurable per user flow.

### Windows Server / On-Premises ADFS

92. **AD FS on Windows Server 2016 — non-Azure O365 issues**: Check WID/SQL sync health, service account permissions, SPN registration for AD FS service account, and application event log on all farm nodes.
93. **AD FS on Windows Server 2019**: Introduces PHS side-by-side with federation, Alternate Login ID improvements, and improved Extranet Smart Lockout.
94. **AD FS on Windows Server 2022**: Adds support for OpenID Connect Refresh Token issuance improvements and enhanced audit logging; review migration notes before upgrade.
95. **Windows 11 Enterprise Multi-Session and AD FS**: AVD multi-session hosts require careful AD FS / SSO configuration; use Entra Join or Hybrid Join with PRT-based SSO for AVD scenarios.

### Miscellaneous Identity Patterns

96. **Alternate Login ID**: Allows users to sign in with email instead of UPN; requires AD FS with Alternate Login ID configuration or Entra ID native support (non-routable UPN workaround).
97. **Token lifetime policy**: `AccessTokenLifetime`, `RefreshTokenMaxInactiveTime`, `RefreshTokenMaxAge` configurable per app or tenant via Token Lifetime Policy; CAE overrides fixed lifetime with event-based revocation.
98. **Claims mapping policy for SAML apps**: JSON policy applied to service principal to customize claims emitted in SAML assertions; supports `TransformationClaimsProvider` for computed claims (e.g., regex extract, join, emit group names).
99. **Application Proxy with header-based SSO**: Connector injects HTTP headers (X-Forwarded-User, custom headers) for apps that consume identity via headers rather than Kerberos; no credential delegation needed.
100. **Entra ID Sign-in diagnostic**: Single-click diagnostic in Entra admin center; takes a User + UPN + date and returns root cause analysis of sign-in failure including CA policy evaluation, MFA result, and error code explanation.
