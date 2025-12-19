# Password Reset Implementation Documentation

## Overview

This document describes the implementation of the password reset functionality for the Personal AI Assistant backend. The implementation follows security best practices and includes:

- Secure token generation
- Email notifications
- Token expiration (1 hour)
- Automatic invalidation of previous tokens
- Session invalidation after password reset
- Comprehensive test coverage

## Architecture

### Components

1. **Model**: `PasswordReset` model in `app/domains/user/models.py`
2. **Service**: Password reset methods in `AuthenticationService`
3. **API**: Two endpoints in `app/domains/user/api/routes.py`
4. **Schemas**: Request/response models in `app/shared/schemas.py`
5. **Email**: Email utility service in `app/core/email.py`
6. **Migration**: Database migration script `migrate_password_resets.py`

### Database Schema

```sql
CREATE TABLE password_resets (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    token VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    is_used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance
CREATE INDEX idx_email_token ON password_resets(email, token);
CREATE INDEX idx_token_expires ON password_resets(token, expires_at);
CREATE INDEX idx_email_unused ON password_resets(email, is_used);
```

## API Endpoints

### 1. Forgot Password

**Endpoint**: `POST /api/v1/auth/forgot-password`

**Request Body**:
```json
{
    "email": "user@example.com"
}
```

**Response**:
```json
{
    "message": "If an account with this email exists, a password reset link has been sent.",
    "token": null,  // Only in development
    "expires_at": null  // Only in development
}
```

**Behavior**:
- Creates a secure UUID token valid for 1 hour
- Invalidates any existing tokens for the email
- Sends email with reset link
- Returns same message whether email exists or not (security)

### 2. Reset Password

**Endpoint**: `POST /api/v1/auth/reset-password`

**Request Body**:
```json
{
    "token": "uuid-token-received-via-email",
    "new_password": "NewSecurePassword123"
}
```

**Response**:
```json
{
    "message": "Password has been successfully reset. Please login with your new password."
}
```

**Behavior**:
- Validates token exists and is not expired/used
- Validates password strength (min 8 characters)
- Updates user password
- Marks token as used
- Invalidates all user sessions (forces re-login)

## Security Features

1. **Token Security**:
   - Uses cryptographically secure UUID tokens
   - Tokens expire after 1 hour
   - Tokens become single-use after successful reset

2. **Email Security**:
   - Doesn't reveal if email exists in forgot password endpoint
   - Tokens sent only to registered email addresses
   - HTML email with click-safe links

3. **Session Security**:
   - All user sessions invalidated after password reset
   - Forces user to re-login with new password

4. **Rate Limiting**:
   - Consider implementing rate limiting on forgot password endpoint
   - Prevents email enumeration attacks

## Email Configuration

Add these to your `.env` file:

```env
# Frontend URL for reset links
FRONTEND_URL=http://localhost:3000

# SMTP Configuration (for production)
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
SMTP_USE_TLS=true
FROM_EMAIL=noreply@personalai.com
FROM_NAME=Personal AI Assistant
```

## Database Migration

Run the migration script to create the password_resets table:

```bash
cd backend
uv run python migrate_password_resets.py
```

To verify the migration:
```bash
uv run python migrate_password_resets.py --verify
```

To rollback (dangerous):
```bash
uv run python migrate_password_resets.py --rollback
```

## Testing

Run the password reset tests:

```bash
cd backend
uv run pytest app/domains/user/tests/test_password_reset.py -v
```

Test coverage includes:
- Token creation and validation
- Password reset flow
- Invalid token handling
- Expired token handling
- Weak password rejection
- API endpoint testing
- Email service testing

## Integration Examples

### Frontend Integration

1. **Forgot Password Form**:
```javascript
async function handleForgotPassword(email) {
    const response = await fetch('/api/v1/auth/forgot-password', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email })
    });

    const data = await response.json();
    // Show success message to user
}
```

2. **Reset Password Form**:
```javascript
async function handleResetPassword(token, newPassword) {
    const response = await fetch('/api/v1/auth/reset-password', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            token,
            new_password: newPassword
        })
    });

    const data = await response.json();
    if (response.ok) {
        // Redirect to login page
        window.location.href = '/login';
    } else {
        // Show error message
    }
}
```

### Email Template Customization

Modify the HTML templates in `app/core/email.py` to match your brand:

- Update colors and styles
- Change logo and branding
- Customize message content
- Add support links

## Production Considerations

1. **Email Service**:
   - Configure SMTP settings for production
   - Consider using transactional email service (SendGrid, SES)
   - Set up email reputation warming

2. **Security**:
   - Implement rate limiting on forgot password endpoint
   - Add CSRF protection
   - Monitor for suspicious activity
   - Log all password reset attempts

3. **Monitoring**:
   - Track password reset success/failure rates
   - Monitor email delivery issues
   - Alert on high volume of requests

4. **Performance**:
   - Database indexes ensure fast lookups
   - Consider caching frequently used tokens
   - Clean up expired tokens periodically

## Troubleshooting

### Common Issues

1. **Token Not Found**:
   - Check if token was copied correctly
   - Verify token hasn't expired
   - Ensure database is properly migrated

2. **Email Not Sending**:
   - Check SMTP configuration
   - Verify email credentials
   - Check spam filters

3. **Password Not Updating**:
   - Verify password strength requirements
   - Check for database connection issues
   - Ensure user exists in database

### Debug Mode

Set environment variable to enable debug logging:
```env
ENVIRONMENT=development
```

This will print email content to console instead of sending.

## Future Enhancements

1. **Features to Consider**:
   - Password history tracking (prevent reuse)
   - Multi-factor authentication for reset
   - Admin-initiated password resets
   - Password strength meter
   - Security questions as backup

2. **Security Improvements**:
   - Token rotation mechanism
   - IP-based rate limiting
   - Browser fingerprinting
   - Suspicious activity detection