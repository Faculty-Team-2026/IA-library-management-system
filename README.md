# Library Management System

A modern, full-stack library management system built with ASP.NET Core and React. This system helps libraries manage their books, users, memberships, and borrowing processes efficiently.

## Features

- 📚 Book Management
  - Add, edit, and remove books
  - Track book locations
  - Monitor book availability

- 👥 User Management
  - User registration and authentication
  - Role-based access control (Librarians, Members)
  - User profile management

- 📖 Borrowing System
  - Book borrowing and returns
  - Borrowing history
  - Request management

- 💳 Membership Management
  - Different membership types
  - Membership status tracking
  - Membership requests

- 💬 Real-time Chat
  - Communication between users
  - Instant notifications
  - SignalR integration

- 🗺️ Location Services
  - Book location tracking
  - Interactive maps using Leaflet

- 🔒 Security Features
  - **AES-256 Encryption** for sensitive data at rest (SSN, Phone numbers)
  - **bcrypt Password Hashing** using bcrypt.NET with salt rounds
  - **JWT Token-Based Authentication** with HS256 algorithm and 12-hour expiration
  - **OAuth2 Single Sign-On (SSO)** - Google integration
  - **Input Validation & Sanitization** to prevent SQL injection and XSS attacks
  - **Rate Limiting** to protect against brute force attacks (5 attempts / 15 min)
  - **Security Headers** for comprehensive browser protection
  - **CORS Protection** with whitelist configuration
  - **Secure coding practices** preventing DoS, SQL injection, and XSS

## Technology Stack

### Backend
- ASP.NET Core 9.0
- Entity Framework Core
- SQL Server
- SignalR for real-time communication
- JWT Authentication
- bcrypt for password hashing
- AES-256 Encryption

### Frontend
- React 18
- TypeScript
- Vite
- TailwindCSS
- Material-UI
- Leaflet for maps
- Axios for API communication

## Security

This project implements comprehensive security measures to protect user data and prevent common vulnerabilities:

### 1. **Encryption** using AES (for sensitive data at rest)
- **Implementation**: AES-256 encryption with 32-byte key and 16-byte IV
- **Location**: `BackEnd/Services/EncryptionService.cs`
- **Protected Data**: SSN, Phone numbers, sensitive user information
- **Key Management**: Base64-encoded keys stored in `appsettings.json`
- **Status**: ✅ Tested and Working

### 2. **Password Hashing** using bcrypt
- **Implementation**: bcrypt.NET library with salt generation
- **Location**: `BackEnd/Services/AuthService.cs`, `BackEnd/Program.cs`
- **Algorithm**: bcrypt with automatic salt (work factor: 12)
- **Usage**: All user passwords, admin credentials, SSO random passwords
- **Status**: ✅ Tested and Working

### 3. **Token-based Authentication** (e.g., JWT or opaque tokens)
- **Implementation**: JWT with HS256 signing algorithm
- **Location**: `BackEnd/Program.cs` (configuration), `BackEnd/Services/AuthService.cs` (generation)
- **Token Lifetime**: 12 hours
- **Claims**: Username, UserId, Role, Email
- **Issuer/Audience**: Configured with validation
- **Status**: ✅ Tested and Working

### 4. **Single Sign-On (SSO)** using OAuth2
- **Provider**: Google
- **Implementation**: Custom OAuth2 integration
- **Location**: `BackEnd/Controllers/SSOController.cs`, `FrontEnd/src/Services/api.ts`
- **Features**: 
  - Automatic user creation from OAuth identity
  - Unique SSN generation per provider/user
  - JWT token generation for SSO users
  - Frontend integration with login buttons
- **Endpoints**:
  - `POST /api/sso/google`
- **Status**: ✅ Tested and Working

### 5. **Secure Coding Practices** to prevent DoS, SQL Injection, and XSS
- **Input Validation**: `BackEnd/Services/ValidationService.cs`
  - Password strength validation (min 8 chars, uppercase, lowercase, numbers, special chars)
  - Email format validation
  - Username validation (alphanumeric + underscores, 3-20 chars)
  - Phone number validation (10-15 digits)
  - SSN format validation
- **XSS Prevention**: HTML encoding and sanitization using `HttpUtility.HtmlEncode`
- **SQL Injection Prevention**: Entity Framework Core with parameterized queries
- **DoS Protection**: Rate limiting service (5 failed attempts / 15 min lockout)
  - Location: `BackEnd/Services/RateLimitingService.cs`
  - Features: Account lockout, attempt tracking, automatic cleanup
- **Security Headers**: 
  - X-Content-Type-Options: nosniff
  - X-Frame-Options: DENY
  - X-XSS-Protection: 1; mode=block
  - Referrer-Policy: no-referrer
  - Content-Security-Policy: default-src 'self'
  - Strict-Transport-Security: max-age=31536000
- **Status**: ✅ Tested and Working

For detailed security information, see [SECURITY.md](./SECURITY.md)

### Password Requirements
- Minimum 8 characters
- Must include uppercase letters (A-Z)
- Must include lowercase letters (a-z)
- Must include numbers (0-9)
- Must include special characters (!@#$%^&*()_+...)

## Prerequisites

- .NET 9.0 SDK
- Node.js (Latest LTS version)
- SQL Server
- Git

## Getting Started

1. Clone the repository:
   ```bash
   git clone https://github.com/Faculty-Team-2026/IA-library-management-system.git
   cd IA-library-management-system
   ```

2. Set up the backend:
   ```bash
   cd BackEnd
   dotnet restore
   dotnet ef database update
   dotnet run
   ```

3. Set up the frontend:
   ```bash
   cd FrontEnd
   npm install
   npm run dev
   ```

4. Open your browser and navigate to `http://localhost:5173`

## Project Structure

```
├── BackEnd/                 # ASP.NET Core backend
│   ├── Controllers/        # API endpoints
│   ├── Models/            # Database entities
│   ├── Services/          # Business logic
│   ├── DTOs/             # Data transfer objects
│   └── Hubs/             # SignalR hubs
├── FrontEnd/               # React frontend
│   ├── src/
│   │   ├── components/   # Reusable components
│   │   ├── Pages/       # Page components
│   │   ├── Services/    # API services
│   │   └── utils/       # Utility functions
│   └── public/           # Static assets
```
