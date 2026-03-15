# Implementation Checklist: Social Authentication Feature

**Document Version**: 1.0
**Date**: 2026-03-15
**Status**: Ready for Implementation

## Pre-Implementation

- [ ] Review existing authentication code
- [ ] Set up Google Cloud OAuth application
- [ ] Set up GitHub OAuth application
- [ ] Add environment variables to `.env` files
- [ ] Review OAuth 2.0 specification for both providers

## Phase 1: Database Schema & Models

### Backend Models

- [ ] Add `SocialProvider` enum to `backend/app/domains/user/models.py`
- [ ] Add `SocialAccount` model to `backend/app/domains/user/models.py`
- [ ] Add `OAuthState` model to `backend/app/domains/user/models.py`
- [ ] Add relationship to `User` model

### Database Migration

- [ ] Create migration file `backend/alembic/versions/008_social_auth.py`
- [ ] Test migration: `cd backend && uv run alembic upgrade head`
- [ ] Verify tables created in database
- [ ] Test rollback: `cd backend && uv run alembic downgrade -1`

## Phase 2: Configuration

### Settings

- [ ] Add `OAuthProviderConfig` class to `backend/app/core/config.py`
- [ ] Add `OAuthSettings` class to `backend/app/core/config.py`
- [ ] Add `oauth` field to main `Settings` class
- [ ] Add environment variables to `.env.example`
- [ ] Test configuration loading

### Environment Variables

```env
# Add to backend/.env
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_REDIRECT_URI=http://localhost:8000/api/v1/auth/oauth/google/callback

GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret
GITHUB_REDIRECT_URI=http://localhost:8000/api/v1/auth/oauth/github/callback
```

## Phase 3: OAuth Service

### Core Service

- [ ] Create `backend/app/domains/user/services/oauth_service.py`
- [ ] Implement `OAuthService.__init__`
- [ ] Implement `get_authorization_url`
- [ ] Implement `handle_callback`
- [ ] Implement `link_account`
- [ ] Implement `unlink_account`
- [ ] Implement `get_linked_accounts`

### Provider Implementations

- [ ] Create `backend/app/domains/user/services/oauth_providers/base.py`
- [ ] Create `backend/app/domains/user/services/oauth_providers/google.py`
- [ ] Create `backend/app/domains/user/services/oauth_providers/github.py`
- [ ] Implement code exchange for Google
- [ ] Implement code exchange for GitHub
- [ ] Implement user info fetch for Google
- [ ] Implement user info fetch for GitHub

### Helper Methods

- [ ] Implement `_validate_state`
- [ ] Implement `_invalidate_state`
- [ ] Implement `_get_provider_config`
- [ ] Implement `_create_user_from_oauth`
- [ ] Implement `_create_social_account`

## Phase 4: API Routes

### Dependencies

- [ ] Add `get_oauth_service` to `backend/app/domains/user/api/dependencies.py`

### Schemas

- [ ] Add `OAuthCallbackRequest` to `backend/app/shared/schemas.py`
- [ ] Add `OAuthUrlResponse` to `backend/app/shared/schemas.py`
- [ ] Add `SocialAccountResponse` to `backend/app/shared/schemas.py`
- [ ] Add `TokenWithNewUser` (extends Token) to `backend/app/shared/schemas.py`

### Endpoints

- [ ] Add `GET /oauth/{provider}/url` endpoint
- [ ] Add `POST /oauth/{provider}/callback` endpoint
- [ ] Add `POST /oauth/{provider}/link` endpoint (authenticated)
- [ ] Add `DELETE /oauth/{provider}/unlink` endpoint (authenticated)
- [ ] Add `GET /oauth/accounts` endpoint (authenticated)

### Error Handling

- [ ] Add `OAuthError` exception to `backend/app/core/exceptions.py`
- [ ] Add `InvalidOAuthStateError` exception
- [ ] Add `OAuthProviderError` exception
- [ ] Add `AccountLinkingError` exception
- [ ] Add exception handlers if needed

## Phase 5: Frontend Data Layer

### Models

- [ ] Create `frontend/lib/features/auth/domain/models/oauth_state.dart`
- [ ] Create `frontend/lib/features/auth/domain/models/social_account.dart`
- [ ] Update `frontend/lib/features/auth/domain/models/auth_response.dart` with `isNewUser`

### Repository Interface

- [ ] Add `getOAuthUrl` to `frontend/lib/features/auth/domain/repositories/auth_repository.dart`
- [ ] Add `handleOAuthCallback` to repository interface
- [ ] Add `linkSocialAccount` to repository interface
- [ ] Add `unlinkSocialAccount` to repository interface
- [ ] Add `getLinkedAccounts` to repository interface

### Remote Datasource

- [ ] Add `getOAuthUrl` to `frontend/lib/features/auth/data/datasources/auth_remote_datasource.dart`
- [ ] Add `handleOAuthCallback` to datasource
- [ ] Add `linkSocialAccount` to datasource
- [ ] Add `unlinkSocialAccount` to datasource
- [ ] Add `getLinkedAccounts` to datasource

### Repository Implementation

- [ ] Implement new methods in `frontend/lib/features/auth/data/repositories/auth_repository_impl.dart`

## Phase 6: Frontend Presentation Layer

### Auth Provider Updates

- [ ] Add `isOAuthLoading` to `AuthState`
- [ ] Add `oauthError` to `AuthState`
- [ ] Implement `initiateOAuthLogin` in `AuthNotifier`
- [ ] Implement `handleOAuthCallback` in `AuthNotifier`
- [ ] Implement `linkSocialAccount` in `AuthNotifier`
- [ ] Implement `unlinkSocialAccount` in `AuthNotifier`
- [ ] Implement `getLinkedAccounts` in `AuthNotifier`

### Widgets

- [ ] Create `frontend/lib/features/auth/presentation/widgets/social_login_buttons.dart`
- [ ] Create `GoogleSignInButton` widget
- [ ] Create `GitHubSignInButton` widget
- [ ] Create `DividerWithText` widget

### Pages

- [ ] Update login page to include social login buttons
- [ ] Update registration page to include social login buttons
- [ ] Create/Update settings page for account linking
- [ ] Handle OAuth callback route

### Deep Linking

- [ ] Configure Android deep link (AndroidManifest.xml)
- [ ] Configure iOS deep link (Info.plist)
- [ ] Configure web redirect handling
- [ ] Test deep link opens app

### Assets

- [ ] Add Google logo asset: `frontend/assets/images/google_logo.png`
- [ ] Update `pubspec.yaml` with asset reference

## Phase 7: Testing

### Backend Unit Tests

- [ ] Create `backend/tests/user/test_oauth_service.py`
- [ ] Test `get_authorization_url` generates valid URL
- [ ] Test state generation and validation
- [ ] Test callback handling for new user
- [ ] Test callback handling for existing user
- [ ] Test account linking
- [ ] Test account unlinking
- [ ] Test provider implementations

### Backend Integration Tests

- [ ] Create `backend/tests/integration/test_oauth_flow.py`
- [ ] Test full OAuth flow (mocked provider)
- [ ] Test API endpoints
- [ ] Test error scenarios

### Frontend Widget Tests

- [ ] Create `frontend/test/widget/auth/social_login_buttons_test.dart`
- [ ] Test button rendering
- [ ] Test button callbacks
- [ ] Test loading states

### Frontend Integration Tests

- [ ] Test OAuth flow in widget tests
- [ ] Test callback handling

### Docker Testing

- [ ] Build Docker image: `cd docker && docker-compose build backend`
- [ ] Start containers: `cd docker && docker-compose up -d`
- [ ] Run tests in container
- [ ] Test OAuth endpoints via curl

## Phase 8: Documentation

### API Documentation

- [ ] Update `specs/api/auth.md` with OAuth endpoints
- [ ] Document request/response formats
- [ ] Document error codes

### Feature Specification

- [ ] Update `specs/features/user/authentication.md`
- [ ] Add OAuth requirements
- [ ] Add flow diagrams

### Setup Guide

- [ ] Document Google Cloud OAuth setup
- [ ] Document GitHub OAuth setup
- [ ] Document environment variables
- [ ] Document deep link configuration

## Phase 9: Code Quality

### Backend

- [ ] Run `cd backend && uv run ruff check .`
- [ ] Run `cd backend && uv run ruff format .`
- [ ] Fix any linting issues
- [ ] Remove debug logging

### Frontend

- [ ] Run `cd frontend && flutter analyze`
- [ ] Run `cd frontend && dart format .`
- [ ] Fix any analysis issues

## Phase 10: Final Verification

### Backend Verification

- [ ] `cd backend && uv sync --extra dev` - completes successfully
- [ ] `cd backend && uv run alembic upgrade head` - migration applies
- [ ] `cd backend && uv run ruff check .` - no errors
- [ ] `cd backend && uv run ruff format .` - formatted
- [ ] All backend tests pass
- [ ] Docker containers start successfully
- [ ] API health check: `curl http://localhost:8000/api/v1/health`

### Frontend Verification

- [ ] `cd frontend && flutter pub get` - completes successfully
- [ ] `cd frontend && flutter test test/widget/` - all tests pass
- [ ] App compiles and runs
- [ ] No runtime errors

### Integration Verification

- [ ] Google login works end-to-end
- [ ] GitHub login works end-to-end
- [ ] New user account creation works
- [ ] Existing user linking works
- [ ] Session management works
- [ ] Logout works for OAuth sessions
- [ ] Token refresh works for OAuth sessions
- [ ] Error messages display correctly (bilingual)

## Post-Implementation

- [ ] Update CHANGELOG.md
- [ ] Create PR with description
- [ ] Request code review
- [ ] Address review feedback
- [ ] Merge to main branch

## Notes

### Critical Path

1. Database migration (Phase 1)
2. OAuth service implementation (Phase 3)
3. API endpoints (Phase 4)
4. Frontend integration (Phase 5-6)

### Dependencies

- Google Cloud OAuth credentials (prerequisite)
- GitHub OAuth credentials (prerequisite)
- Deep link configuration (for mobile)

### Estimated Timeline

- Backend: 8-10 hours
- Frontend: 6-8 hours
- Testing: 4 hours
- Documentation: 2 hours
- **Total: 20-24 hours**

### Risk Areas

1. OAuth state management security
2. Account linking edge cases
3. Deep link configuration on mobile
4. Provider API changes
