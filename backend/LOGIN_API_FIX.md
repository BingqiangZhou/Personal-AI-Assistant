# Login API Field Mismatch Fix

## Problem
The Test Engineer identified a critical API compatibility issue:
- **Backend API** expected the field name `email_or_username` for login
- **Frontend** was sending the field name `username`
- This caused all login requests to fail with validation errors

## Solution
Updated the `LoginRequest` schema in `backend/app/domains/user/api/routes.py` to accept **both** field names for backward compatibility.

### Changes Made

#### 1. Updated LoginRequest Schema
```python
class LoginRequest(BaseModel):
    """Login request schema."""
    username: Optional[str] = Field(None, description="Username for login (alternative to email_or_username)")
    email_or_username: Optional[str] = Field(None, description="Email or username for login (alternative to username)")
    password: str

    @model_validator(mode='before')
    @classmethod
    def validate_identifier(cls, data):
        """Ensure either username or email_or_username is provided."""
        if isinstance(data, dict):
            if not data.get('username') and not data.get('email_or_username'):
                raise ValueError('Either username or email_or_username must be provided')
        return data
```

#### 2. Updated Login Endpoint Logic
```python
@router.post("/login", response_model=Token)
async def login(
    login_data: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db_session)
) -> Any:
    """Login with email/username and password."""
    try:
        auth_service = AuthenticationService(db)

        # Determine which field to use (username takes priority if both provided)
        identifier = login_data.username or login_data.email_or_username

        # Authenticate user
        user = await auth_service.authenticate_user(
            email_or_username=identifier,
            password=login_data.password
        )
```

### Implementation Details

1. **Field Priority**: If both `username` and `email_or_username` are provided, `username` takes precedence
2. **Validation**: At least one of the two fields must be provided
3. **Backward Compatibility**: Existing clients using `email_or_username` will continue to work
4. **Forward Compatibility**: New clients can use the simpler `username` field

### Testing

The fix supports the following login request formats:

#### Using `username` field (new):
```json
{
    "username": "testuser123",
    "password": "password123"
}
```

#### Using `email_or_username` field (original):
```json
{
    "email_or_username": "testuser123",
    "password": "password123"
}
```

#### Using both fields (username takes priority):
```json
{
    "username": "testuser123",
    "email_or_username": "will_be_ignored",
    "password": "password123"
}
```

### Server Restart Required

The backend server needs to be restarted to apply these changes:
```bash
cd backend
uv run uvicorn app.main:app --reload
```

## Summary

This fix resolves the critical login issue by making the API flexible enough to accept both field names, ensuring compatibility between the frontend and backend without breaking existing integrations.