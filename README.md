
# 🚀 NestJS Authentication Kit

A production-ready authentication and authorization starter kit for NestJS, pre-configured with **secure cookie-based sessions**, **refresh token rotation**,  **email verification**, and **device/session tracking** — all running seamlessly in **Docker** with **NGINX** as a reverse proxy.

This kit includes **database abstraction layers** for **MongoDB** (via Mongoose) and **MariaDB** (via TypeORM). MongoDB is the default, but you can switch to MariaDB with minimal changes.

No need to worry about ports — just access your API via `http://localhost/auth/`.

## 🎥 Demo Video

[![Watch the Demo](https://img.youtube.com/vi/XJ6jzP9O5Bo/maxresdefault.jpg)](https://www.youtube.com/watch?v=XJ6jzP9O5Bo)

## 📌 Features

- 🔐 **Secure cookie-based authentication** (HttpOnly, Secure cookies — no JWT in localStorage)
- 🔁 **Refresh token rotation** with revocation: rotated refresh tokens on each use to protect against replay attacks
- 📧 Email verification & password reset via OTP
- 📱 Session management with device tracking and session revocation
- 🖥 Integrated **NGINX reverse proxy** for clean URLs (`http://localhost/auth/`) — no ports required
- 🐳 **Docker & docker-compose** setup for instant local development
- 🚀 One-command build & start process (`docker-compose up --build -d`)
- 📜 Swagger API documentation at `/auth/docs`
- 🗄 **Database abstraction layer** for:
  - **MongoDB** with Mongoose (default)
  - **MariaDB** with TypeORM (plug-and-play)
- 🔌 Plugin-extensible architecture for custom auth strategies and providers

## 🔁 Refresh Token Rotation (with session regeneration)

This kit implements **refresh token rotation with session regeneration** to minimize the impact of stolen refresh tokens and detect replay attacks.

High-level flow (what happens on `POST /auth/refresh`):

1. The client sends the existing refresh token (HttpOnly cookie) to `/auth/refresh`.
2. The server verifies the refresh token and extracts the payload (user id, token type, session id, etc.).
3. The server **creates a new session id** (server-side session entry) and persists it (device info, ip, current refresh token hash, etc.). This step is performed by `setSessionToken(...)`.
4. The server issues a new access token and sets it as a (HttpOnly) cookie using `setAuthToken(...)`. The access token is tied to the **new session id**.
5. The server generates a **new refresh token**, stores a hash of it against the new session entry, and sets it as a (HttpOnly) cookie using `setRefreshToken(...)`.
6. The server returns a success response (e.g. `{ status: 200, message: 'Refresh token generated successfully!' }`).

**Why regenerate session id?**
- Rotating session id on refresh ties newly-issued tokens to a fresh server-side session record. If an attacker reuses an old refresh token, you can detect that the token’s session id no longer matches the most recent session record and revoke the session(s) immediately.
- Regenerating session id reduces attack window and simplifies detection/forensics (you always know which session is newest).

**Important security rules**
- Persist the new session record (and the hash of the new refresh token or new jti) *before* you set cookies on the client — this avoids race conditions where a client holds a cookie for which no server-side session exists.
- If you detect reuse of an old refresh token (incoming refresh token does not match the stored hash/jti), **revoke the whole session (or optionally all user sessions)** and require re-login.
- Use short-lived access tokens (e.g., 10–15 minutes) and rotate refresh tokens frequently (e.g., 30 days expiry).
- Cookies should be `HttpOnly`, `Secure` (in production), and use an appropriate `SameSite` policy.

## Installation

```
# Clone the repository

git clone https://github.com/skylineCodes/nestjs-auth-starter-kit

# Navigate into the project

cd nestjs-auth-starter-kit

# Build and start using Docker Compose
docker-compose up --build -d

```

## 🚀 Running the API
Once `docker-compose` is up, the API will be available via **NGINX** at:

```
http://localhost/auth/
```
No port is required in the URL — NGINX handles the proxy and routing.

## 📜 API Documentation
Swagger docs are available at:

```
http://localhost:3001/auth-service-docs/
```

## 🛡 Security Considerations

-   Always use **Secure** cookies in production (`COOKIE_SECURE=true`)
-   Keep your `.env` file out of version control
-   Rotate your JWT secret periodically
-   Use HTTPS in production with NGINX TLS configuration

## 🧪 Testing
``` 
npm run test 
```

## 📄 License

MIT License — feel free to use, modify, and distribute with attribution.

## 🤝 Contributing

We welcome contributions from the community!  
Whether it's bug fixes, new features, or improving documentation, your help is appreciated.

### 📝 How to Contribute

1.  **Fork the repository**  
    Click the **Fork** button on GitHub to create your own copy.
    
2.  **Clone your fork locally**
```
git clone https://github.com/skylineCodes/nestjs-auth-starter-kit

cd nestjs-auth-starter-kit
```

3. **Create a new branch**  
Use a descriptive name for your branch:
```
git checkout -b feature/add-password-reset
```

4.  **Make your changes**
    
    -   Follow the coding style guidelines.
        
    -   Ensure all tests pass (`npm run test` inside the container).
        
    -   Update/add documentation if necessary.
        
5.   **Commit your changes**
```
git commit -m "Add password reset functionality"
```
6.   **Push to your fork**
```
git push origin feature/add-password-reset
```
7. **Create a Pull Request**  
Go to your fork on GitHub and open a pull request to the `main` branch of this repo.

### 📏 Coding Style

-   Use **Prettier** for formatting and **ESLint** for linting.
    
-   Follow NestJS module structure (controllers, services, DTOs, entities/schemas).
    
-   Keep functions small and focused — single responsibility principle.
    
-   Use TypeScript types/interfaces everywhere possible.

### 🔀 Branching Strategy

We follow a simplified **Git Flow**:

-   **main** → Production-ready code only
    
-   **develop** → Integration branch for testing before merging into `main`
    
-   **feature/** → New features (merge into `develop`)
    
-   **bugfix/** → Fixes for existing code
    
-   **hotfix/** → Urgent fixes for production (merge into `main` and `develop`)

