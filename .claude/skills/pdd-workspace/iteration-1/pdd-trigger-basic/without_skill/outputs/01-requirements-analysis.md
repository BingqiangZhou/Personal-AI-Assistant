# Requirements Analysis: Social Authentication Feature

**Document Version**: 1.0
**Date**: 2026-03-15
**Status**: Draft

## 1. Executive Summary

This document analyzes the requirements for implementing social authentication (OAuth 2.0) to complement the existing email/password authentication system. The feature will enable users to authenticate using Google and GitHub as identity providers.

## 2. Current State Analysis

### 2.1 Existing Authentication System

The codebase already implements a robust JWT-based authentication system:

**Backend (`backend/app/domains/user/`)**:
- `services/auth_service.py`: Core authentication logic
- `api/routes.py`: REST API endpoints
- `models.py`: User, UserSession, PasswordReset models

**Frontend (`frontend/lib/features/auth/`)**:
- `presentation/providers/auth_provider.dart`: Riverpod state management
- `domain/models/`: User, AuthRequest, AuthResponse models
- `data/repositories/auth_repository_impl.dart`: API communication

**Current Features**:
- Email/password registration and login
- Username-based login (alternative to email)
- JWT access tokens (1 hour expiry)
- Refresh tokens with sliding sessions (7 or 30 days)
- Password reset via email
- Session management (max 5 concurrent sessions)
- 2FA support infrastructure (totp_secret, is_2fa_enabled fields)

### 2.2 Gaps Identified

1. No OAuth 2.0 / social login support
2. No external identity provider integration
3. No account linking mechanism

## 3. Requirements

### 3.1 Functional Requirements

| ID | Requirement | Priority | Description |
|----|-------------|----------|-------------|
| FR-1 | Google OAuth Login | High | Users can authenticate using Google account |
| FR-2 | GitHub OAuth Login | High | Users can authenticate using GitHub account |
| FR-3 | Account Linking | High | Link social accounts to existing email-based accounts |
| FR-4 | Account Creation | High | Auto-create accounts for new social users |
| FR-5 | Profile Sync | Medium | Sync profile data (name, avatar) from social providers |
| FR-6 | Session Management | High | Social logins follow same session rules as email/password |
| FR-7 | Logout | High | Logout works for social-authenticated sessions |
| FR-8 | Token Refresh | High | Refresh tokens work for social sessions |

### 3.2 Non-Functional Requirements

| ID | Requirement | Priority | Description |
|----|-------------|----------|-------------|
| NFR-1 | Security | Critical | OAuth state parameter for CSRF protection |
| NFR-2 | Privacy | High | Minimal scope requests (email, profile only) |
| NFR-3 | Performance | Medium | OAuth callback processing < 500ms |
| NFR-4 | Reliability | High | Graceful handling of provider outages |
| NFR-5 | UX | High | Seamless redirect flow with return URL preservation |

### 3.3 Technical Constraints

1. Must integrate with existing `AuthenticationService`
2. Must use existing `UserSession` model for session management
3. Must follow existing API response format (bilingual errors)
4. Must work with existing frontend auth provider pattern
5. Backend uses `uv` (not pip), `ruff` (not black/isort/flake8)
6. Frontend uses Material 3, Riverpod for state management

## 4. OAuth 2.0 Flow Design

### 4.1 Authorization Code Flow (Recommended)

```
┌─────────┐     ┌─────────┐     ┌─────────┐     ┌─────────┐
│  User   │     │ Frontend│     │ Backend │     │ Provider│
└────┬────┘     └────┬────┘     └────┬────┘     └────┬────┘
     │               │               │               │
     │ 1. Click Login│               │               │
     │──────────────>│               │               │
     │               │               │               │
     │               │ 2. GET /auth/{provider}/url  │
     │               │──────────────>│               │
     │               │               │               │
     │               │ 3. Return OAuth URL + state  │
     │               │<──────────────│               │
     │               │               │               │
     │ 4. Redirect to Provider       │               │
     │<──────────────│               │               │
     │               │               │               │
     │ 5. User authenticates with Provider          │
     │───────────────────────────────────────────────>
     │               │               │               │
     │ 6. Redirect to callback URL with code + state│
     │<───────────────────────────────────────────────
     │               │               │               │
     │ 7. Send code to frontend callback             │
     │──────────────>│               │               │
     │               │               │               │
     │               │ 8. POST /auth/{provider}/callback
     │               │──────────────>│               │
     │               │               │               │
     │               │               │ 9. Exchange code for tokens
     │               │               │──────────────>│
     │               │               │               │
     │               │               │ 10. Return user info
     │               │               │<──────────────│
     │               │               │               │
     │               │ 11. Return JWT tokens         │
     │               │<──────────────│               │
     │               │               │               │
     │ 12. Authenticated state       │               │
     │<──────────────│               │               │
```

### 4.2 State Parameter Security

The OAuth state parameter must:
1. Be cryptographically random (32+ bytes)
2. Be stored server-side with expiry (5 minutes)
3. Include provider identifier
4. Be single-use (invalidated after callback)

## 5. Data Model Changes

### 5.1 New Model: SocialAccount

```python
class SocialAccount(Base):
    """Social account linking for OAuth providers."""
    __tablename__ = "social_accounts"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    provider = Column(String(20), nullable=False)  # 'google', 'github'
    provider_user_id = Column(String(255), nullable=False)  # ID from provider
    provider_email = Column(String(255), nullable=True)
    access_token = Column(Text, nullable=True)  # Encrypted
    refresh_token = Column(Text, nullable=True)  # Encrypted
    token_expires_at = Column(DateTime(timezone=True), nullable=True)
    profile_data = Column(JSON, nullable=True)  # Cached profile info
    created_at = Column(DateTime(timezone=True), default=datetime.now(UTC))
    updated_at = Column(DateTime(timezone=True), onupdate=datetime.now(UTC))

    __table_args__ = (
        UniqueConstraint("provider", "provider_user_id", name="uq_social_provider_user"),
        Index("idx_social_user_provider", "user_id", "provider"),
    )
```

### 5.2 New Model: OAuthState

```python
class OAuthState(Base):
    """OAuth state for CSRF protection."""
    __tablename__ = "oauth_states"

    id = Column(Integer, primary_key=True)
    state = Column(String(64), unique=True, nullable=False)
    provider = Column(String(20), nullable=False)
    redirect_uri = Column(String(500), nullable=True)
    created_at = Column(DateTime(timezone=True), default=datetime.now(UTC))
    expires_at = Column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        Index("idx_oauth_state_expires", "state", "expires_at"),
    )
```

### 5.3 User Model Extensions

Add to existing `User` model:
- No changes required (email is already unique and nullable=false)

## 6. API Endpoints

### 6.1 New Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/auth/oauth/{provider}/url` | Get OAuth authorization URL |
| POST | `/api/v1/auth/oauth/{provider}/callback` | Handle OAuth callback |
| POST | `/api/v1/auth/oauth/{provider}/link` | Link social account to existing user |
| DELETE | `/api/v1/auth/oauth/{provider}/unlink` | Unlink social account |
| GET | `/api/v1/auth/oauth/accounts` | List linked social accounts |

### 6.2 Endpoint Specifications

#### GET /api/v1/auth/oauth/{provider}/url

**Path Parameters**:
- `provider`: "google" | "github"

**Query Parameters**:
- `redirect_uri` (optional): Frontend callback URL

**Response**:
```json
{
  "authorization_url": "https://accounts.google.com/o/oauth2/v2/auth?...",
  "state": "random_state_string"
}
```

#### POST /api/v1/auth/oauth/{provider}/callback

**Path Parameters**:
- `provider`: "google" | "github"

**Request Body**:
```json
{
  "code": "authorization_code_from_provider",
  "state": "state_string_from_step_1"
}
```

**Response** (New User):
```json
{
  "access_token": "jwt_access_token",
  "refresh_token": "jwt_refresh_token",
  "token_type": "Bearer",
  "expires_in": 3600,
  "is_new_user": true
}
```

**Response** (Existing User):
```json
{
  "access_token": "jwt_access_token",
  "refresh_token": "jwt_refresh_token",
  "token_type": "Bearer",
  "expires_in": 3600,
  "is_new_user": false
}
```

## 7. Configuration Requirements

### 7.1 Backend Environment Variables

```env
# Google OAuth
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_REDIRECT_URI=https://your-domain.com/api/v1/auth/oauth/google/callback

# GitHub OAuth
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret
GITHUB_REDIRECT_URI=https://your-domain.com/api/v1/auth/oauth/github/callback
```

### 7.2 Frontend Configuration

```dart
class OAuthConfig {
  static const String googleProvider = 'google';
  static const String githubProvider = 'github';
  static const String callbackScheme = 'myapp';  // For deep linking
}
```

## 8. Provider-Specific Details

### 8.1 Google OAuth

**Scopes Required**:
- `openid` - OpenID Connect
- `email` - User email
- `profile` - Basic profile info

**Token Endpoint**: `https://oauth2.googleapis.com/token`
**User Info Endpoint**: `https://www.googleapis.com/oauth2/v2/userinfo`

### 8.2 GitHub OAuth

**Scopes Required**:
- `user:email` - Access to email addresses

**Token Endpoint**: `https://github.com/login/oauth/access_token`
**User Info Endpoint**: `https://api.github.com/user`
**Email Endpoint**: `https://api.github.com/user/emails`

## 9. Security Considerations

1. **CSRF Protection**: Use state parameter with server-side validation
2. **Token Encryption**: Encrypt provider tokens at rest
3. **Scope Minimization**: Request only necessary scopes
4. **Email Verification**: Trust provider's email verification status
5. **Account Conflict**: Handle case where social email matches existing account
6. **Rate Limiting**: Apply same rate limits as email/password auth

## 10. Success Criteria

- [ ] Users can login with Google
- [ ] Users can login with GitHub
- [ ] New accounts are auto-created from social profiles
- [ ] Existing accounts can be linked to social providers
- [ ] Session management works identically for social auth
- [ ] Logout clears social-authenticated sessions
- [ ] Token refresh works for social sessions
- [ ] Error handling provides bilingual messages
- [ ] All tests pass (backend and frontend)
- [ ] Docker deployment works

## 11. Dependencies

### 11.1 Backend (Python)

Potential packages to add:
- `httpx` (already in dev dependencies) - for async HTTP to OAuth providers
- `authlib` - OAuth client library (optional, can use httpx directly)

### 11.2 Frontend (Flutter)

- No additional packages required (use existing dio_client)
- Optional: `flutter_appauth` for native mobile OAuth

## 12. Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Provider API changes | Low | Medium | Version API calls, add integration tests |
| Provider outage | Low | High | Graceful error messages, fallback to email |
| Email conflict | Medium | Medium | Account linking with user confirmation |
| Token theft | Low | High | Short-lived tokens, secure storage |
