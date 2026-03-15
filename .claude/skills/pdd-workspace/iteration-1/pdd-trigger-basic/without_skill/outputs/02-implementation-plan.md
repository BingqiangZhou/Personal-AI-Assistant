# Implementation Plan: Social Authentication Feature

**Document Version**: 1.0
**Date**: 2026-03-15
**Status**: Draft

## 1. Overview

This plan outlines the implementation steps for adding Google and GitHub OAuth authentication to the existing authentication system. The implementation follows the project's established patterns and conventions.

## 2. Architecture Design

### 2.1 Backend Structure

```
backend/app/
├── domains/
│   └── user/
│       ├── api/
│       │   ├── routes.py          # Add OAuth endpoints
│       │   └── dependencies.py    # Add OAuth service dependency
│       ├── services/
│       │   ├── auth_service.py    # Existing (minor modifications)
│       │   └── oauth_service.py   # NEW: OAuth provider handling
│       ├── models.py              # Add SocialAccount, OAuthState models
│       └── schemas.py             # NEW: OAuth request/response schemas
├── core/
│   ├── config.py                  # Add OAuth config settings
│   └── security.py                # Add state generation/validation
└── shared/
    └── schemas.py                 # Add shared OAuth schemas
```

### 2.2 Frontend Structure

```
frontend/lib/
├── features/
│   └── auth/
│       ├── data/
│       │   ├── datasources/
│       │   │   └── auth_remote_datasource.dart  # Add OAuth API calls
│       │   └── repositories/
│       │       └── auth_repository_impl.dart    # Add OAuth methods
│       ├── domain/
│       │   ├── models/
│       │   │   ├── oauth_state.dart             # NEW
│       │   │   └── social_account.dart          # NEW
│       │   └── repositories/
│       │       └── auth_repository.dart         # Add OAuth methods
│       └── presentation/
│           ├── providers/
│           │   └── auth_provider.dart           # Add OAuth actions
│           └── widgets/
│               └── social_login_buttons.dart    # NEW
└── core/
    └── app/
        └── config/
            └── app_config.dart                  # Add OAuth config
```

## 3. Implementation Phases

### Phase 1: Database Schema & Models (Backend)

**Priority**: Critical
**Estimated Effort**: 2 hours

#### Tasks

1. **Create Alembic Migration**
   - File: `backend/alembic/versions/008_social_auth.py`
   - Create `social_accounts` table
   - Create `oauth_states` table

2. **Add Models to models.py**
   - `SocialAccount` model
   - `OAuthState` model

#### Code Changes

**backend/app/domains/user/models.py** - Add:

```python
class SocialProvider(StrEnum):
    """Supported OAuth providers."""
    GOOGLE = "google"
    GITHUB = "github"


class SocialAccount(Base):
    """Social account linking for OAuth providers."""
    __tablename__ = "social_accounts"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    provider = Column(String(20), nullable=False)
    provider_user_id = Column(String(255), nullable=False)
    provider_email = Column(String(255), nullable=True)
    access_token = Column(Text, nullable=True)
    refresh_token = Column(Text, nullable=True)
    token_expires_at = Column(DateTime(timezone=True), nullable=True)
    profile_data = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC), onupdate=lambda: datetime.now(UTC))

    user = relationship("User", backref="social_accounts")

    __table_args__ = (
        UniqueConstraint("provider", "provider_user_id", name="uq_social_provider_user"),
        Index("idx_social_user_provider", "user_id", "provider"),
    )


class OAuthState(Base):
    """OAuth state for CSRF protection."""
    __tablename__ = "oauth_states"

    id = Column(Integer, primary_key=True, index=True)
    state = Column(String(64), unique=True, nullable=False, index=True)
    provider = Column(String(20), nullable=False)
    redirect_uri = Column(String(500), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    expires_at = Column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        Index("idx_oauth_state_expires", "state", "expires_at"),
    )
```

### Phase 2: Configuration (Backend)

**Priority**: Critical
**Estimated Effort**: 1 hour

#### Tasks

1. **Update core/config.py**
   - Add OAuth configuration settings class
   - Add provider-specific settings

#### Code Changes

**backend/app/core/config.py** - Add:

```python
class OAuthSettings(BaseSettings):
    """OAuth provider configuration."""

    # Google
    google_client_id: str = ""
    google_client_secret: str = ""
    google_redirect_uri: str = ""

    # GitHub
    github_client_id: str = ""
    github_client_secret: str = ""
    github_redirect_uri: str = ""

    # OAuth State
    oauth_state_expire_minutes: int = 5

    model_config = SettingsConfigDict(env_prefix="OAUTH_", env_file=".env")


# Update Settings class
class Settings(BaseSettings):
    # ... existing settings ...
    oauth: OAuthSettings = OAuthSettings()
```

### Phase 3: OAuth Service (Backend)

**Priority**: Critical
**Estimated Effort**: 4 hours

#### Tasks

1. **Create OAuth Service**
   - File: `backend/app/domains/user/services/oauth_service.py`
   - Implement provider-specific OAuth flows
   - Implement state management
   - Implement account linking logic

#### Key Methods

```python
class OAuthService:
    """Service for handling OAuth authentication."""

    async def get_authorization_url(
        self,
        provider: SocialProvider,
        redirect_uri: str | None = None,
    ) -> dict[str, str]:
        """Generate OAuth authorization URL with state."""
        ...

    async def handle_callback(
        self,
        provider: SocialProvider,
        code: str,
        state: str,
        request: Request,
    ) -> dict[str, Any]:
        """Handle OAuth callback and create/link user."""
        ...

    async def link_account(
        self,
        user: User,
        provider: SocialProvider,
        code: str,
        state: str,
    ) -> SocialAccount:
        """Link social account to existing user."""
        ...

    async def unlink_account(
        self,
        user: User,
        provider: SocialProvider,
    ) -> bool:
        """Unlink social account from user."""
        ...

    async def get_linked_accounts(
        self,
        user: User,
    ) -> list[SocialAccount]:
        """Get all linked social accounts for user."""
        ...
```

### Phase 4: API Routes (Backend)

**Priority**: Critical
**Estimated Effort**: 2 hours

#### Tasks

1. **Update API Routes**
   - File: `backend/app/domains/user/api/routes.py`
   - Add OAuth endpoints

#### New Endpoints

```python
@router.get("/oauth/{provider}/url")
async def get_oauth_url(
    provider: str,
    redirect_uri: str | None = None,
    oauth_service: OAuthService = Depends(get_oauth_service),
) -> dict[str, str]:
    """Get OAuth authorization URL."""
    ...

@router.post("/oauth/{provider}/callback")
async def oauth_callback(
    provider: str,
    callback_data: OAuthCallbackRequest,
    request: Request,
    oauth_service: OAuthService = Depends(get_oauth_service),
    auth_service: AuthenticationService = Depends(get_authentication_service),
) -> Token:
    """Handle OAuth callback."""
    ...

@router.post("/oauth/{provider}/link")
async def link_oauth_account(
    provider: str,
    callback_data: OAuthCallbackRequest,
    current_user: User = Depends(get_current_user),
    oauth_service: OAuthService = Depends(get_oauth_service),
) -> dict[str, str]:
    """Link social account to current user."""
    ...

@router.delete("/oauth/{provider}/unlink")
async def unlink_oauth_account(
    provider: str,
    current_user: User = Depends(get_current_user),
    oauth_service: OAuthService = Depends(get_oauth_service),
) -> dict[str, str]:
    """Unlink social account."""
    ...

@router.get("/oauth/accounts")
async def get_oauth_accounts(
    current_user: User = Depends(get_current_user),
    oauth_service: OAuthService = Depends(get_oauth_service),
) -> list[SocialAccountResponse]:
    """Get linked social accounts."""
    ...
```

### Phase 5: Frontend Data Layer

**Priority**: High
**Estimated Effort**: 3 hours

#### Tasks

1. **Update Auth Models**
   - Add `OAuthState` model
   - Add `SocialAccount` model
   - Update `AuthResponse` with `is_new_user` field

2. **Update Auth Remote Datasource**
   - Add OAuth API methods

3. **Update Auth Repository**
   - Add OAuth repository methods

#### Code Changes

**frontend/lib/features/auth/domain/models/oauth_state.dart**:

```dart
import 'package:freezed_annotation/freezed_annotation.dart';

part 'oauth_state.freezed.dart';
part 'oauth_state.g.dart';

@freezed
class OAuthState with _$OAuthState {
  const factory OAuthState({
    required String authorizationUrl,
    required String state,
  }) = _OAuthState;

  factory OAuthState.fromJson(Map<String, dynamic> json) =>
      _$OAuthStateFromJson(json);
}
```

**frontend/lib/features/auth/data/datasources/auth_remote_datasource.dart** - Add:

```dart
Future<OAuthState> getOAuthUrl(String provider, {String? redirectUri});
Future<AuthResponse> oauthCallback(String provider, String code, String state);
Future<void> linkOAuthAccount(String provider, String code, String state);
Future<void> unlinkOAuthAccount(String provider);
Future<List<SocialAccount>> getLinkedAccounts();
```

### Phase 6: Frontend Presentation Layer

**Priority**: High
**Estimated Effort**: 3 hours

#### Tasks

1. **Update Auth Provider**
   - Add OAuth state management
   - Add OAuth action methods

2. **Create Social Login Buttons Widget**
   - Google sign-in button
   - GitHub sign-in button

3. **Handle OAuth Redirect Flow**
   - Implement redirect handler
   - Implement callback processing

#### Code Changes

**frontend/lib/features/auth/presentation/providers/auth_provider.dart** - Add:

```dart
// Add to AuthState
final bool? isOAuthLoading;
final String? oauthError;

// Add to AuthNotifier
Future<void> initiateOAuthLogin(String provider) async { ... }
Future<void> handleOAuthCallback(String provider, String code, String state) async { ... }
Future<void> linkSocialAccount(String provider) async { ... }
Future<void> unlinkSocialAccount(String provider) async { ... }
Future<List<SocialAccount>> getLinkedAccounts() async { ... }
```

**frontend/lib/features/auth/presentation/widgets/social_login_buttons.dart**:

```dart
class SocialLoginButtons extends ConsumerWidget {
  const SocialLoginButtons({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    return Column(
      children: [
        _GoogleSignInButton(
          onPressed: () => ref.read(authProvider.notifier).initiateOAuthLogin('google'),
        ),
        const SizedBox(height: 12),
        _GitHubSignInButton(
          onPressed: () => ref.read(authProvider.notifier).initiateOAuthLogin('github'),
        ),
      ],
    );
  }
}
```

### Phase 7: Testing

**Priority**: High
**Estimated Effort**: 4 hours

#### Tasks

1. **Backend Unit Tests**
   - OAuth service tests
   - State generation/validation tests
   - Account linking tests

2. **Backend Integration Tests**
   - Full OAuth flow tests (mocked providers)
   - API endpoint tests

3. **Frontend Widget Tests**
   - Social login button tests
   - OAuth callback handling tests

#### Test Files

- `backend/tests/user/test_oauth_service.py`
- `backend/tests/integration/test_oauth_flow.py`
- `frontend/test/widget/auth/social_login_buttons_test.dart`

### Phase 8: Documentation

**Priority**: Medium
**Estimated Effort**: 2 hours

#### Tasks

1. **Update API Specification**
   - File: `specs/api/auth.md`
   - Add OAuth endpoints documentation

2. **Update Feature Specification**
   - File: `specs/features/user/authentication.md`
   - Add OAuth requirements and flows

3. **Update README/Setup Guide**
   - Add OAuth provider setup instructions

## 4. Implementation Sequence

```
Week 1:
├── Day 1-2: Phase 1 (Database) + Phase 2 (Config)
├── Day 3-4: Phase 3 (OAuth Service)
└── Day 5: Phase 4 (API Routes)

Week 2:
├── Day 1-2: Phase 5 (Frontend Data Layer)
├── Day 3-4: Phase 6 (Frontend Presentation)
└── Day 5: Phase 7 (Testing) + Phase 8 (Docs)
```

## 5. Verification Checklist

### Backend

- [ ] `uv sync --extra dev` completes successfully
- [ ] `uv run alembic upgrade head` applies migration
- [ ] `uv run ruff check .` passes
- [ ] `uv run ruff format .` passes
- [ ] All tests pass in Docker
- [ ] API responds to `/api/v1/health`
- [ ] OAuth URLs generated correctly
- [ ] Callback processing works

### Frontend

- [ ] `flutter pub get` completes
- [ ] `flutter test test/widget/` passes
- [ ] App compiles and runs
- [ ] Social buttons render correctly
- [ ] OAuth flow completes

### Integration

- [ ] Google login works end-to-end
- [ ] GitHub login works end-to-end
- [ ] Account linking works
- [ ] Session management works
- [ ] Logout works for OAuth sessions

## 6. Rollback Plan

If issues arise:

1. **Database**: Alembic downgrade to previous version
2. **Backend**: Revert route changes, disable OAuth endpoints
3. **Frontend**: Hide social login buttons, revert provider changes
4. **Feature Flag**: Add `OAUTH_ENABLED=false` config option

## 7. Post-Implementation

### Monitoring

- Log OAuth success/failure rates
- Monitor provider response times
- Track account linking conflicts

### Future Enhancements

- Additional providers (Microsoft, Apple, Twitter)
- Native mobile OAuth (AppAuth)
- Token refresh for provider APIs
- Profile sync scheduling
