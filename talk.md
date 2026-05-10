
# Note

## AADSTS

https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes

## Application and Service Principal

1. Entities

entity
  └── directoryObject        ← base type, has `id`, `deletedDateTime`
        ├── user
        ├── group
        ├── device
        ├── application       ← app registration
        ├── servicePrincipal  ← instantiation of app in a tenant
        └── orgContact

2. App registration and Service Principal (Enterprise Application)
    - SP in tenants are implementations for App registration in HOME tenant
    - App registrations defines the trust relationship and auth method
    - SP defines the role and grants consents
    - Conditional Access Policy is tenant-scoped hence works on SP

3. TSG for federated identity and MI
    - Federated credential: secretless auth for workloads (app reg or user-assigned MI)
        - trust chain: external IdP token → Entra validates signature + claims → issues Entra token
        - step 1 — signature validation (cryptographic, before any claim check):
            - Entra fetches OIDC discovery doc from issuer URL: {issuer}/.well-known/openid-configuration
            - extracts jwks_uri → fetches JWKS (JSON Web Key Set) = the IdP's public keys
            - validates token's signature against those public keys with algo like RS256
            - if JWKS endpoint is down or keys rotated mid-flight → signature validation fails
        - step 2 — three claim fields that MUST match exactly:
            - issuer (iss): the OIDC issuer URL of external IdP (e.g. https://token.actions.githubusercontent.com)
            - subject (sub): identifies the specific workload (e.g. repo:contoso/app:ref:refs/heads/main)
            - audience (aud): must be api://AzureADTokenExchange (default) or custom
    - Managed Identity (MI):
        - token acquisition: workload calls IMDS (169.254.169.254:80/metadata/identity/oauth2/token)
            - Azure SDK → DefaultAzureCredential chain tries MI automatically
            - GET http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01
                &resource=https://management.azure.com/
                &client_id=<user-assigned-MI-client-id>   ← only needed for user-assigned MI

4. Enterprise Apps SSO troubleshooting (claims config, URI config, sign-in failures)
    - SSO protocol choice on Enterprise App: SAML 2.0, OIDC, Password-based, Linked (URL)
        - Only OIDC based SSO with broker app can be used on public app
    - SAML SSO config: Identifier (Entity ID), Entra SAML assertion, claim mapping
    - OIDC SSO config: optional claims (groups, email, upn) added in app registration manifest


## Role and Scope & claims

1. Access token claims
- https://learn.microsoft.com/en-us/entra/identity-platform/developer-glossary#scopes

- role claim and scp claim
    - `scp` (scope) (Delegated Permission): space-separated delegated permissions the USER consented to
        - "Mail.Read Files.Read"
        - the API checks scp to know what the calling user allowed the app to do on their behalf
    - `roles` (app role) (Application Permission): permissions granted to the APPLICATION itself, no user context
        - present in app-only tokens (client credentials flow)
        - user can be assigned appRoles <-> NOT Azure RBAC, Azure RBAC never a claim
    - `wids` -> Entra directory roles

## Microsoft Entra Governance, Compliance and Reporting

1. Access Review /identityGovernance/accessReviews/definitions/{id}/instances/{id}/decisions
    - periodic recertification: reviewer (manager/owner/self) confirms each user still needs access
    - scope: group membership, app assignments, Entra roles, Azure resource roles
    - outcome: auto-remove on denial or require manual remediation; Access review creation and group/app review operations [TODO]

2. Audit Log
    - records every write operation in the tenant: user created, role assigned, policy changed, consent granted
    - retention: 7 days (free), 30 days (P1/P2); export to Log Analytics / Storage Account / Event Hub for longer
    - query via Entra portal → Audit logs, or Graph API: GET /auditLogs/directoryAudits?$filter=...

3. Identity Protection
    - detects risky users (leaked credentials, anomalous behavior) and risky sign-ins (impossible travel, unfamiliar location)
    - risk levels: low / medium / high; feeds into CA as a signal (require MFA or block on high risk)
    - investigation: Identity Protection → Risky users / Risky sign-ins → review detections → remediate (reset password, dismiss, confirm compromise) [TODO]

## AD 

#### 1 Directorios

┌─────────────────────────────────┐   ┌─────────────────────────────┐
│  AD DS (on-prem)                │   │  Entra ID (cloud)           │
│  ──────────────                 │   │  ────────────               │
│  Storage: NTDS.dit              │   │  Storage: Azure-managed     │
│  Schema: X.500-based, rigid     │   │  Schema: OData/Graph-based  │
│  Protocol: LDAP (389/636)       │   │  Protocol: MS Graph REST API│
│  Auth: Kerberos + NTLM          │   │  Auth: OAuth 2.0 / OIDC    │
│  Scope: forest / domain         │   │  Scope: tenant              │
│                                 │   │                             │
│  Objects:                       │   │  Objects:                   │
│    user, computer, group,       │   │    user, device, group,     │
│    organizationalUnit,          │   │    application,             │
│    serviceAccount               │   │    servicePrincipal         │
│                                 │   │                             │
│  Namespace: DN                  │   │  Namespace: objectId (GUID) │
│    CN=Alice,OU=Users,           │   │    id: 8a7b3c...            │
│    DC=contoso,DC=com            │   │    upn: alice@contoso.com   │
└─────────────┬───────────────────┘   └──────────────┬──────────────┘
              └─────────── SYNC (#2)  ───────────────┘

- 2 protocols are different -> use sync tech
- Directory lifecycle: creating, deleting, linking directory to subscription [TODO]
- Data residency and region availability [TODO]

#### LDAP

- schema based protocol for talking to AD DS
  dn: CN=Alice Smith,OU=Users,DC=contoso,DC=com
  objectClass: top, person, organizationalPerson, user    ← schema classes
  cn: Alice Smith
  sAMAccountName: asmith
  DC=com                                     ← root
  └── DC=contoso                             ← domain component
      ├── OU=Users                           ← organizational unit
      │   ├── CN=Alice Smith                 ← leaf (user entry)

### 2. sync

┌────────┐    LDAP read    ┌────────┐    SCIM REST API   ┌──────────┐
│ AD DS  │ ───────────────►│Entra ID│ ──────────────────►│Salesforce│
└────────┘                 └────────┘                     └──────────┘
        Entra Connect INBOUND      Entra Provisioning OUTBOUND
         (installed on-prem)            (cloud service)

#### INBOUND SYNC (Entra Connect):

- Object Translation
    - AD DS objects : users, groups, contacts, devices → Entra ID objects
    - sourceAnchor is the immutable JOIN KEY joining AD DS object -> Entra ID object
    - use ms-DS-ConsistencyGuid (preferred) or objectGUID to be the sourceAnchor
    
- Attribute transformation for Object Translation
    AD DS                          Entra ID
    ────                           ────────
    sAMAccountName                 onPremisesSamAccountName
    userPrincipalName              userPrincipalName
    objectGUID                     onPremisesImmutableId (Base64)
    ms-DS-ConsistencyGuid          sourceAnchor (join key)
    - not all fields can correspond

- Hybrid Azure AD Join for non-matchable device type
    - [TODO] https://learn.microsoft.com/en-us/entra/identity/devices/how-to-hybrid-join

- Sync cycles
    - Delta sync: every 30 minutes
        0. track changes with USN (Update Sequence Number)
        1. Import from AD DS with LDAP delta query → AD Connector Space (cache)
        2. Sync AD CS → Metaverse (apply inbound sync rules like one object one record)
        3. Sync Metaverse → AAD CS (apply outbound sync rules)
        4. Export to Entra ID (Graph API calls from AAD Connector Space)
    - Password hash sync (PHS): every 2 minutes
        - use MS-DRSR protocol
    - Full sync: manual trigger only (expensive)


#### OUTBOUND PROVISIONING (SCIM):

- On Entra ID events, SCIM requests updating users are sent to SAAS

REST API based Protocol for provisioning users into apps: SCIM 2.0 (RFC 7644)
    POST /Users          → create user in SaaS app
    PATCH /Users/{id}    → update attributes
    DELETE /Users/{id}   → deprovision

### 3. authN (setup for Entra Connect)


- PHS (Password Hash Sync)
    - hash-of-hash passwd stores in EntraID
        - 1-layer NTLM hash (MD4-based) doesnot have salt -> wrap the 2nd salted-hash
    - fastest: no on-prem dependency at login
    - leaked credential detection
    - risk: hash in cloud (mitigated: it's a hash of a hash)

- PTA (Pass-Through Authentication)
    - password forwarded to ON-PREM agents via Service Bus (Queue)
        - on-prem agent can long-poll in persistent connection for queued passwd
        - agent then puts auth result back to service bus
    - enables: on-prem password policy enforcement
    - preinstalled on-prem agent is error-prone (Microsoft Azure AD Connect Authentication Agent)

- Federation (AD FS)
    - 302 redirect Browser to AD FS based on domain
    - AD FS check auth with AD DS using LDAP and redirected back to EntraID
    - Internet -> WAP in DMZ -> AD FS in corp net -> AD DS
    - WAP is a L7 reverse proxy knowing WS-Fed and enables pre-authentication
        - Entra App Proxy is its modern replacement

- on-prem agent is error-prone in PTA -> PHS as backup (PHS is resilient)
- Migration direction: Federation → PTA → PHS

### 4. authN to authZ

- Token issue after authN
    - On-prem
        - AD DS issues: Kerberos TGT + service tickets
        - AD FS issues: SAML assertions, WS-Fed tokens, OIDC tokens
    - Cloud
        - Entra ID issues: OAuth 2.0 access_tokens, OIDC id_tokens, refresh_tokens

- SSO
    - On-prem -> scope: domain / forest
        - Kerberos TGT → cached by Windows → presented to any kerberized app
        - Scope: domain/forest
    - Cloud
        - PRT cached by WAM/broker at OS level
        - Scope: all Entra ID-integrated apps on the device
        - Protected by: TPM binding (hardware key)
    - Bridge (Seamless SSO):
        - Kerberos TGT → service ticket (ST) for AZUREADSSOACC → Entra ID validates ST
        - Only works with PHS or PTA as `401 WWW-AUthenticate=Negotiate` has to be returned by Entra instead of the 302

- Device SSO matrix:
    - Domain-Joined (on-prem only)
        - TGT for on-prem
        - No cloud SSO
    - Hybrid Joined (both)
        - TGT + PRT
        - SSO everywhere
    - Entra Joined (cloud only)
        - PRT only
        - No on-prem SSO

### 5. Conditional Access Policy and PIM

0. authN done
1. Check assignment on SP
2. check consent by user / admin on SP
    - User consent for delegated permission
    - Admin consent for all users
3. conditional access
4. PIM activation check
    - role is eligible but NOT activated -> NO role claim in token

#### PIM

- Inject short-lived priviledged role after extra auth steps
- Entra directory roles : PIM inject role claim to JWT
- Azure resource roles : no role claim in JWT just ARM use API check

#### CA Policy (P1 needed)

- CA inputs (signals):
    - WHO: user, group, role, guest vs member
    - WHAT: which app (client_id)
    - WHERE: IP (named location), country
    - HOW: device state, compliance, join type
    - RISK: sign-in risk, user risk (Identity Protection, P2)

- CA output (decision):
    - BLOCK: deny access
    - GRANT: allow, possibly with controls:
        - Require MFA or compliance device or hybrid join or authN strength
        - Compliance device : Intune MDM → enrolls device → pushes compliance policy → evaluates
        - authN strength
            - CBA (certificate based authentication)
            - FIDO 2 (HW security key -> yubi key)
            - Windows Hello for bussiness

- Auth broker holds centralized PRT for all apps so enables SSO and policy
    - Mobile: Microsoft Authenticator / Company Portal
    - Windows: WAM (Web Account Manager)
    - macOS: Microsoft Enterprise SSO extension

- Licensing gating:
    - FREE: Security Defaults (all or nothing — MFA for all, block legacy auth)
    - P1: Conditional Access, App Proxy, PTA / Seamless SSO, SSPR, custom roles
    - P2: Identity Protection, PIM, Access Reviews, Entitlement Mgmt, risk-based CA
    - Security Defaults is mutually exclusive with named CA policies

- MFA sign-in troubleshooting (unable to sign-in due to MFA, unexpected MFA prompt) [TODO]
- CA "What-If" tool and resultant set of policy troubleshooting [TODO]

### 6. tenant boundary

A tenant is a TRUST BOUNDARY. Three models for crossing it:

- MODEL A: B2B (Guest access)
    - external user invited into YOUR tenant → gets guest object in your directory
    - Auth: Alice authenticates at Fabrikam (her home IdP)
    - Token: Entra ID issues contoso-scoped tokens for Alice
    - Access: limited by UserType=Guest defaults + CA policies
    - Lifecycle: invitation-based or Entitlement Management
    - Use case: partner collaboration, vendor access

- MODEL B: B2C / External ID (Customer identity)
    - customer signs up in a SEPARATE external tenant you own for them
    - Auth: Google (social IdP) or local account (email+password)
    - Token: external tenant issues tokens
    - Directory: user object in external tenant, NOT in corp tenant
    - Access: only to the specific app they signed up for
    - Lifecycle: self-service sign-up, self-service delete
    - Custom policies (IEF): XML-based user journey; needed for REST API calls mid-auth,
      complex branching, step-up MFA, attribute transformation beyond user flows
    - Use case: consumer app, e-commerce, patient portal

- MODEL C: Cross-tenant access settings (org-to-org)
    - two tenants configure bilateral trust for shared claims
    - e.g. Contoso trusts Fabrikam's MFA claims → guests don't re-MFA in resource tenant
    - e.g. Fabrikam trusts Contoso's device compliance
    - Use case: M&A, multi-subsidiary orgs, strategic partnerships

- B2B: external user lives in YOUR directory as a guest
    - can access: SharePoint, Teams, any enterprise app you assign
- B2C: external user lives in a SEPARATE directory you own for them
    - can access: only the specific app, nothing else in your corp tenant
    - B2C User Flows: tokens, sessions, security [TODO]
    - B2C data residency and region availability [TODO]

## OAuth2.0 and OIDC

[TODO]
- Claim
    - https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens

https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols

1. OAuth2.0 authorization code for az login
    - [1hr] https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow 
    - `state` query string stores at Client side to prevent CSRF attack
        - without it Eve can hand Alice her /callback to trick Alice to act under Eve's session (AUTH_CODE_VALUE)
    - PKCE : one-way-hash from code-verifier to code-challenger
        - code-challenge sent -> auth on /authorize -> code-verifier sent for server to verify -> issue token by /token
        - let server verify if the client before and after /authorize is the same
    - AUTH_CODE is used so Agent doesnot hold real access_token
                                Web App (confidential)       az login (public client)
                            ──────────────────────       ───────────────────────
    client_secret           ✅ YES (server has it)       ❌ NO (CLI has no secret)
    PKCE required?          Recommended                  MANDATORY (only proof of caller)
    redirect_uri            https://myapp.com/callback   http://localhost:{random_port}
    Token storage           Server session (memory/DB)   ~/.azure/msal_token_cache.json
    Session cookie?         Yes → browser gets cookie    No → CLI stores tokens locally
    client_id               Your app's ID                04b07795-8ddb-... (Azure CLI)
    scope                   Your API scopes              management.azure.com/.default
2. OIDC
    - OIDC ID token has client itself as `aud` [TODO]
    - OIDC Discovery /{tenant}/v2.0/.well-known/openid-configuration
        - need tenant to contain blast radius
3. OIDC and OAuth2.0 build dependency
    - [TODO]
4. Workload identity and federated credential
    - The external workload (such as a GitHub Actions workflow) requests a token from the external IdP (such as GitHub).
    - The external IdP issues a token to the external workload.
    - The external workload (the sign in action in a GitHub workflow, for example) sends the token to Microsoft identity platform and requests an access token.
    - Microsoft identity platform checks the trust relationship on the user-assigned managed identity or app registration and validates the external token against the OpenID Connect (OIDC) issuer URL on the external IdP. [TODO]
    - When the checks are satisfied, Microsoft identity platform issues an access token to the external workload.
    - The external workload accesses Microsoft Entra protected resources using the access token from Microsoft identity platform. A GitHub Actions workflow, for example, uses the access token to publish a web app to Azure App Service.
    - App Registration: "my-deploy-app" (client_id = abc-123) -> Federated Credential:
        issuer:   https://token.actions.githubusercontent.com
        subject:  repo:contoso/webapp:ref:refs/heads/main
        audience: api://AzureADTokenExchange
    - https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation
    - https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation-create-trust?pivots=identity-wif-apps-methods-azp#important-considerations-and-restrictions
5. OAuth2.0 OBO
    User ──authenticates──► Entra ID ──token A (aud=API A)──► App
    App  ──token A──► API A
    API A ──token A as assertion──► Entra ID ──token B (aud=API B)──► API A
    API A ──token B──► API B
    Auth Code + PKCE token (first-party, user directly authorized):
    {
        "sub":   "alice-oid",
        "scp":   "Mail.Read Files.Read",     ← delegated scope
        "aud":   "api://my-api",
        "azp":   "client-app-id",            ← who requested the token (the SPA/web app)
        "acr":   "1",
        "amr":   ["pwd", "mfa"]              ← how alice authenticated
    }
    OBO token (downstream, alice forwarded by API A):
    {
        "sub":   "alice-oid",                ← same alice
        "scp":   "Mail.Read",               ← downstream scope
        "aud":   "api://api-b",
        "azp":   "api-a-client-id",          ← NOW points to API A, not the original app
        "acct":  ...,
    }
6. OAuth2.0 Client credentials flow
    - callback url not needed as there is no 302

### Graph API unifies endpoints from products

- Graph API v.s. Data Connect
    - Graph API: real-time, per-request, user/app delegated or app-only, throttled (rate limits per tenant)
        - use for: live reads/writes, user-facing apps, automation, single-object operations
    - Data Connect: bulk export of Microsoft 365 data to Azure Data Lake / Synapse via Azure Data Factory pipelines
        - use for: analytics, compliance, ML — reading thousands/millions of objects without throttling
        - requires admin consent + Microsoft 365 E3/E5; data lands in your Azure subscription, not real-time
    - rule of thumb: Graph API for operational access, Data Connect for analytical bulk extraction
    - https://developer.microsoft.com/en-us/graph/graph-explorer
- MS Search API
    - https://learn.microsoft.com/en-us/graph/search-concept-overview
- Graph API troubleshooting:
    - 504 Gateway Timeout: large result sets or complex queries exceed backend timeout
    - OData query string appending url
        - $top pagination
        - $select to reduce payload
        - break into smaller $filter windows