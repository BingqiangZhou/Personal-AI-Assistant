# Technical Design: Social Authentication Feature

**Document Version**: 1.0
**Date**: 2026-03-15
**Status**: Draft

## 1. OAuth 2.0 Flow Implementation

### 1.1 Authorization URL Generation

```python
# backend/app/domains/user/services/oauth_service.py

class OAuthService:
    async def get_authorization_url(
        self,
        provider: SocialProvider,
        redirect_uri: str | None = None,
    ) -> dict[str, str]:
        """Generate OAuth authorization URL with state parameter."""
        # Generate secure state
        state = secrets.token_urlsafe(32)

        # Store state in database with expiry
        oauth_state = OAuthState(
            state=state,
            provider=provider.value,
            redirect_uri=redirect_uri,
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
        )
        self.db.add(oauth_state)
        await self.db.commit()

        # Get provider configuration
        config = self._get_provider_config(provider)

        # Build authorization URL
        params = {
            "client_id": config.client_id,
            "redirect_uri": config.redirect_uri,
            "response_type": "code",
            "scope": config.scope,
            "state": state,
            "access_type": "offline",  # For refresh tokens
            "prompt": "consent",  # Force consent screen
        }

        authorization_url = f"{config.authorization_url}?{urlencode(params)}"

        return {
            "authorization_url": authorization_url,
            "state": state,
        }
```

### 1.2 Callback Processing

```python
async def handle_callback(
    self,
    provider: SocialProvider,
    code: str,
    state: str,
    request: Request,
) -> dict[str, Any]:
    """Handle OAuth callback and create/link user."""
    # Validate state
    oauth_state = await self._validate_state(state, provider)
    if not oauth_state:
        raise UnauthorizedError("Invalid or expired OAuth state")

    # Exchange code for tokens
    token_data = await self._exchange_code_for_tokens(provider, code)

    # Get user info from provider
    user_info = await self._get_user_info(provider, token_data["access_token"])

    # Check for existing social account
    social_account = await self._get_social_account(
        provider, user_info["id"]
    )

    if social_account:
        # Existing linked account - just login
        user = await self._get_user_by_id(social_account.user_id)
        is_new_user = False
    else:
        # Check for existing user with same email
        existing_user = await self._get_user_by_email(user_info["email"])

        if existing_user:
            # Link to existing account
            social_account = await self._create_social_account(
                existing_user, provider, user_info, token_data
            )
            user = existing_user
            is_new_user = False
        else:
            # Create new user
            user = await self._create_user_from_oauth(provider, user_info)
            social_account = await self._create_social_account(
                user, provider, user_info, token_data
            )
            is_new_user = True

    # Create session
    session_data = await self._auth_service.create_user_session(
        user=user,
        device_info={"oauth_provider": provider.value},
        ip_address=request.client.host,
        user_agent=request.headers.get("user-agent"),
    )

    # Invalidate used state
    await self._invalidate_state(oauth_state)

    return {
        **session_data,
        "is_new_user": is_new_user,
    }
```

## 2. Provider-Specific Implementations

### 2.1 Google OAuth

```python
class GoogleOAuthProvider:
    """Google OAuth 2.0 implementation."""

    AUTHORIZATION_URL = "https://accounts.google.com/o/oauth2/v2/auth"
    TOKEN_URL = "https://oauth2.googleapis.com/token"
    USER_INFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"
    SCOPE = "openid email profile"

    async def exchange_code(self, code: str, config: OAuthProviderConfig) -> dict:
        """Exchange authorization code for tokens."""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                self.TOKEN_URL,
                data={
                    "client_id": config.client_id,
                    "client_secret": config.client_secret,
                    "code": code,
                    "grant_type": "authorization_code",
                    "redirect_uri": config.redirect_uri,
                },
            )
            response.raise_for_status()
            return response.json()

    async def get_user_info(self, access_token: str) -> dict:
        """Get user info from Google."""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                self.USER_INFO_URL,
                headers={"Authorization": f"Bearer {access_token}"},
            )
            response.raise_for_status()
            data = response.json()

            return {
                "id": data["id"],
                "email": data["email"],
                "email_verified": data.get("verified_email", False),
                "name": data.get("name"),
                "given_name": data.get("given_name"),
                "family_name": data.get("family_name"),
                "picture": data.get("picture"),
                "locale": data.get("locale"),
            }
```

### 2.2 GitHub OAuth

```python
class GitHubOAuthProvider:
    """GitHub OAuth 2.0 implementation."""

    AUTHORIZATION_URL = "https://github.com/login/oauth/authorize"
    TOKEN_URL = "https://github.com/login/oauth/access_token"
    USER_INFO_URL = "https://api.github.com/user"
    USER_EMAIL_URL = "https://api.github.com/user/emails"
    SCOPE = "user:email"

    async def exchange_code(self, code: str, config: OAuthProviderConfig) -> dict:
        """Exchange authorization code for tokens."""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                self.TOKEN_URL,
                headers={"Accept": "application/json"},
                data={
                    "client_id": config.client_id,
                    "client_secret": config.client_secret,
                    "code": code,
                    "redirect_uri": config.redirect_uri,
                },
            )
            response.raise_for_status()
            return response.json()

    async def get_user_info(self, access_token: str) -> dict:
        """Get user info from GitHub."""
        async with httpx.AsyncClient() as client:
            # Get basic user info
            user_response = await client.get(
                self.USER_INFO_URL,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/json",
                },
            )
            user_response.raise_for_status()
            user_data = user_response.json()

            # Get email addresses (may be private)
            email_response = await client.get(
                self.USER_EMAIL_URL,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/json",
                },
            )
            emails = email_response.json() if email_response.status_code == 200 else []

            # Find primary verified email
            primary_email = next(
                (e for e in emails if e.get("primary") and e.get("verified")),
                emails[0] if emails else {"email": user_data.get("email")},
            )

            return {
                "id": str(user_data["id"]),
                "email": primary_email.get("email"),
                "email_verified": primary_email.get("verified", False),
                "name": user_data.get("name") or user_data.get("login"),
                "username": user_data.get("login"),
                "picture": user_data.get("avatar_url"),
                "bio": user_data.get("bio"),
                "location": user_data.get("location"),
                "blog": user_data.get("blog"),
            }
```

## 3. Frontend Implementation

### 3.1 OAuth Flow Handler

```dart
// frontend/lib/features/auth/presentation/providers/oauth_handler.dart

class OAuthHandler {
  final AuthRepository _authRepository;
  final DioClient _dioClient;

  Future<void> initiateOAuthLogin(String provider) async {
    // Get authorization URL from backend
    final response = await _authRepository.getOAuthUrl(provider);

    // Store state for validation
    await _secureStorage.saveOAuthState(
      provider: provider,
      state: response.state,
    );

    // Open browser for OAuth
    final uri = Uri.parse(response.authorizationUrl);
    if (await canLaunchUrl(uri)) {
      await launchUrl(uri, mode: LaunchMode.externalApplication);
    } else {
      throw Exception('Could not launch OAuth URL');
    }
  }

  Future<void> handleOAuthCallback(
    String provider,
    String code,
    String state,
  ) async {
    // Validate state
    final savedState = await _secureStorage.getOAuthState(provider);
    if (savedState != state) {
      throw Exception('Invalid OAuth state');
    }

    // Clear stored state
    await _secureStorage.clearOAuthState(provider);

    // Send callback to backend
    final response = await _authRepository.handleOAuthCallback(
      provider: provider,
      code: code,
      state: state,
    );

    // Store tokens
    await _secureStorage.saveAccessToken(response.accessToken);
    await _secureStorage.saveRefreshToken(response.refreshToken);

    return response;
  }
}
```

### 3.2 Deep Link Configuration

**Android (android/app/src/main/AndroidManifest.xml)**:

```xml
<intent-filter>
    <action android:name="android.intent.action.VIEW" />
    <category android:name="android.intent.category.DEFAULT" />
    <category android:name="android.intent.category.BROWSABLE" />
    <data android:scheme="myapp" android:host="oauth-callback" />
</intent-filter>
```

**iOS (ios/Runner/Info.plist)**:

```xml
<key>CFBundleURLTypes</key>
<array>
    <dict>
        <key>CFBundleURLSchemes</key>
        <array>
            <string>myapp</string>
        </array>
    </dict>
</array>
```

**Web (index.html)**:

```html
<!-- For web, use the redirect URI directly -->
```

### 3.3 Social Login Button Widget

```dart
// frontend/lib/features/auth/presentation/widgets/social_login_buttons.dart

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

class SocialLoginButtons extends ConsumerWidget {
  const SocialLoginButtons({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final authState = ref.watch(authProvider);
    final isLoading = authState.isOAuthLoading ?? false;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        _DividerWithText(text: 'OR'),
        const SizedBox(height: 24),
        _GoogleSignInButton(
          onPressed: isLoading
              ? null
              : () => ref.read(authProvider.notifier).initiateOAuthLogin('google'),
          isLoading: isLoading,
        ),
        const SizedBox(height: 12),
        _GitHubSignInButton(
          onPressed: isLoading
              ? null
              : () => ref.read(authProvider.notifier).initiateOAuthLogin('github'),
          isLoading: isLoading,
        ),
      ],
    );
  }
}

class _GoogleSignInButton extends StatelessWidget {
  final VoidCallback? onPressed;
  final bool isLoading;

  const _GoogleSignInButton({
    this.onPressed,
    this.isLoading = false,
  });

  @override
  Widget build(BuildContext context) {
    return OutlinedButton.icon(
      onPressed: onPressed,
      icon: isLoading
          ? const SizedBox(
              width: 18,
              height: 18,
              child: CircularProgressIndicator(strokeWidth: 2),
            )
          : Image.asset(
              'assets/images/google_logo.png',
              width: 18,
              height: 18,
            ),
      label: Text(
        isLoading ? 'Signing in...' : 'Continue with Google',
        style: Theme.of(context).textTheme.bodyLarge,
      ),
      style: OutlinedButton.styleFrom(
        padding: const EdgeInsets.symmetric(vertical: 12, horizontal: 16),
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(8),
        ),
      ),
    );
  }
}

class _GitHubSignInButton extends StatelessWidget {
  final VoidCallback? onPressed;
  final bool isLoading;

  const _GitHubSignInButton({
    this.onPressed,
    this.isLoading = false,
  });

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;

    return OutlinedButton.icon(
      onPressed: onPressed,
      icon: isLoading
          ? const SizedBox(
              width: 18,
              height: 18,
              child: CircularProgressIndicator(strokeWidth: 2),
            )
          : Icon(
              Icons.code,
              size: 18,
              color: isDark ? Colors.white : Colors.black87,
            ),
      label: Text(
        isLoading ? 'Signing in...' : 'Continue with GitHub',
        style: Theme.of(context).textTheme.bodyLarge,
      ),
      style: OutlinedButton.styleFrom(
        padding: const EdgeInsets.symmetric(vertical: 12, horizontal: 16),
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(8),
        ),
      ),
    );
  }
}

class _DividerWithText extends StatelessWidget {
  final String text;

  const _DividerWithText({required this.text});

  @override
  Widget build(BuildContext context) {
    return Row(
      children: [
        Expanded(child: Divider(color: Theme.of(context).dividerColor)),
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 16),
          child: Text(
            text,
            style: Theme.of(context).textTheme.bodySmall,
          ),
        ),
        Expanded(child: Divider(color: Theme.of(context).dividerColor)),
      ],
    );
  }
}
```

## 4. Database Migration

```python
# backend/alembic/versions/008_social_auth.py

"""Add social authentication tables

Revision ID: 008
Revises: 007
Create Date: 2026-03-15

"""
from alembic import op
import sqlalchemy as sa

revision = '008'
down_revision = '007'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create social_accounts table
    op.create_table(
        'social_accounts',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('provider', sa.String(20), nullable=False),
        sa.Column('provider_user_id', sa.String(255), nullable=False),
        sa.Column('provider_email', sa.String(255), nullable=True),
        sa.Column('access_token', sa.Text(), nullable=True),
        sa.Column('refresh_token', sa.Text(), nullable=True),
        sa.Column('token_expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('profile_data', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('provider', 'provider_user_id', name='uq_social_provider_user'),
    )
    op.create_index('idx_social_user_provider', 'social_accounts', ['user_id', 'provider'])

    # Create oauth_states table
    op.create_table(
        'oauth_states',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('state', sa.String(64), nullable=False),
        sa.Column('provider', sa.String(20), nullable=False),
        sa.Column('redirect_uri', sa.String(500), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('state'),
    )
    op.create_index('idx_oauth_state_expires', 'oauth_states', ['state', 'expires_at'])


def downgrade() -> None:
    op.drop_index('idx_oauth_state_expires', table_name='oauth_states')
    op.drop_table('oauth_states')
    op.drop_index('idx_social_user_provider', table_name='social_accounts')
    op.drop_table('social_accounts')
```

## 5. Error Handling

### 5.1 Error Responses

```python
# backend/app/core/exceptions.py - Add OAuth-specific exceptions

class OAuthError(BaseCustomError):
    """Base OAuth error."""
    def __init__(
        self,
        message_en: str,
        message_zh: str,
        provider: str | None = None,
    ):
        super().__init__(message_en, message_zh)
        self.provider = provider


class InvalidOAuthStateError(OAuthError):
    """Invalid or expired OAuth state."""
    def __init__(self):
        super().__init__(
            message_en="OAuth session expired. Please try again.",
            message_zh="OAuth 会话已过期，请重试。",
        )


class OAuthProviderError(OAuthError):
    """Error from OAuth provider."""
    def __init__(self, provider: str, detail: str = ""):
        super().__init__(
            message_en=f"Authentication with {provider} failed. {detail}",
            message_zh=f"{provider} 认证失败。{detail}",
            provider=provider,
        )


class AccountLinkingError(OAuthError):
    """Error linking accounts."""
    def __init__(self, email: str):
        super().__init__(
            message_en=f"An account with {email} already exists. Please login first to link your social account.",
            message_zh=f"邮箱 {email} 已存在。请先登录以关联您的社交账户。",
        )
```

### 5.2 Frontend Error Handling

```dart
// frontend/lib/core/network/exceptions/oauth_exceptions.dart

class OAuthException implements Exception {
  final String message;
  final String? provider;

  OAuthException(this.message, {this.provider});

  @override
  String toString() => message;
}

class InvalidOAuthStateException extends OAuthException {
  InvalidOAuthStateException()
      : super('OAuth session expired. Please try again.');
}

class OAuthProviderException extends OAuthException {
  OAuthProviderException(String provider, [String? detail])
      : super('Authentication with $provider failed. ${detail ?? ""}', provider: provider);
}
```

## 6. Security Checklist

- [ ] State parameter is cryptographically random (32+ bytes)
- [ ] State expires after 5 minutes
- [ ] State is single-use (invalidated after callback)
- [ ] Provider tokens are encrypted at rest
- [ ] HTTPS required for all OAuth endpoints
- [ ] Redirect URI validation
- [ ] Rate limiting on OAuth endpoints
- [ ] Audit logging for OAuth events
- [ ] Email verification status from provider is trusted
- [ ] Account linking requires user confirmation

## 7. Configuration Checklist

### Provider Setup

**Google Cloud Console**:
1. Create OAuth 2.0 Client ID
2. Add authorized redirect URIs
3. Enable Google+ API

**GitHub Developer Settings**:
1. Create OAuth App
2. Set Authorization callback URL
3. Generate client secret

### Environment Variables

```env
# Required for production
GOOGLE_CLIENT_ID=xxx
GOOGLE_CLIENT_SECRET=xxx
GOOGLE_REDIRECT_URI=https://api.example.com/api/v1/auth/oauth/google/callback

GITHUB_CLIENT_ID=xxx
GITHUB_CLIENT_SECRET=xxx
GITHUB_REDIRECT_URI=https://api.example.com/api/v1/auth/oauth/github/callback

# Optional
OAUTH_STATE_EXPIRY_MINUTES=5
OAUTH_ENCRYPT_TOKENS=true
```
