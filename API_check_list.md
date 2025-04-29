# API Security Checklist

> A checklist of the most important security countermeasures when designing, testing, and releasing your API.

---

## 🔐 Authentication

- ❌ Don't use Basic Auth. Use standard authentication (e.g., JWT).
- 🔁 Don't reinvent the wheel in authentication, token generation, and password storage — use established standards.
- 🚫 Use max retry limits and jail features on login endpoints.
- 🔒 Encrypt all sensitive data in transit and at rest.

---

## 🪪 JWT (JSON Web Token)

- 🔑 Use a random, complex secret key to prevent brute-forcing.
- ⚙️ Don't trust the algorithm in the header — enforce it server-side (e.g., `HS256`, `RS256`).
- ⏱️ Set short token expiration times (`TTL`, `RTTL`).
- 🕵️‍♂️ Don't store sensitive data in JWT payloads — they're easily decoded.
- 📦 Keep JWTs small. They are often sent in headers, which have size limits.

---

## 🚦 Access Control

- 📉 Apply request throttling to prevent DDoS and brute-force attacks.
- 🌐 Use HTTPS with **TLS 1.2+** and strong ciphers.
- 📛 Set `Strict-Transport-Security` (HSTS) headers to prevent SSL stripping.
- 🚫 Disable directory listings on the server.
- 🛂 For private APIs, allow access only from safelisted IPs or hostnames.

---

## ✅ Authorization / OAuth

- 🔄 Validate `redirect_uri` server-side to allow only trusted URLs.
- 🧾 Prefer exchanging authorization codes instead of tokens directly (`response_type=code` only).
- 🧬 Use the `state` parameter with a random value to prevent CSRF.
- 🎯 Set default scopes and validate requested scopes per application.

---

## 🧪 Input Validation & Handling

- 🔧 Use correct HTTP methods (GET, POST, PUT, DELETE) and return `405 Method Not Allowed` for unsupported methods.
- 🧾 Validate the `Accept` header to ensure supported formats (`406 Not Acceptable` for unsupported ones).
- 🧼 Validate posted content-types (`application/json`, `multipart/form-data`, etc.).
- 🧯 Sanitize and validate all user inputs to prevent XSS, SQLi, RCE, etc.
- 🚷 Never expose credentials, passwords, tokens, or API keys in URLs — use the `Authorization` header.
- 🔐 Encrypt data only on the server side.
- 🌉 Use API gateways for rate-limiting, caching, and dynamic routing.

---

## ⚙️ Processing

- 🔒 Ensure all endpoints are protected by proper authentication.
- 👤 Avoid exposing user IDs — prefer `/me/orders` over `/user/654321/orders`.
- 🆔 Use UUIDs instead of auto-incremented IDs.
- 📄 Disable entity parsing in XML to prevent XXE attacks.
- 💥 Avoid entity expansion in XML/YAML to mitigate Billion Laughs attacks.
- 🖼️ Use CDNs for file uploads.
- 🏗️ Use workers/queues for heavy tasks to keep APIs responsive.
- 🚫 Turn off `DEBUG` mode in production.
- 🧱 Use non-executable stacks where supported.

---

## 📤 Output

- 🧯 Send `X-Content-Type-Options: nosniff`.
- 🚫 Send `X-Frame-Options: deny`.
- 🛡️ Set `Content-Security-Policy: default-src 'none'`.
- ❌ Remove fingerprinting headers (`X-Powered-By`, `Server`, `X-AspNet-Version`, etc.).
- 📄 Explicitly set response `Content-Type` (e.g., `application/json`).
- 🔐 Never return sensitive data (credentials, passwords, tokens).
- 🚦 Return appropriate HTTP status codes (e.g., `200 OK`, `400 Bad Request`, `401 Unauthorized`, etc.).

---

## 🏗️ CI & CD

- 🔍 Audit code with unit/integration test coverage.
- 🧑‍⚖️ Implement peer reviews — no self-approvals.
- 🧼 Run antivirus/static scans on all components and dependencies.
- 🔐 Use continuous security testing (SAST/DAST).
- 📦 Monitor dependencies for known vulnerabilities.
- 🛠️ Design and test rollback strategies.

---

## 📊 Monitoring

- 🗃️ Centralize logs across services and components.
- 📡 Monitor traffic, errors, and request/response logs.
- 🚨 Set up alerts via SMS, Email, Slack, Telegram, Kibana, CloudWatch, etc.
- 🔏 Avoid logging sensitive data like passwords, PINs, and credit cards.
- 🕵️ Use IDS/IPS systems to monitor and alert on suspicious API activity.

---
