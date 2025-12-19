# Manual Test Script: Forgot Password Functionality

## Test Environment Setup
- **Frontend URL**: http://127.0.0.1:61730/
- **Backend API**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs

## Pre-test Requirements
1. Backend server should be running (`uv run uvicorn app.main:app --reload`)
2. Flutter app should be running (`flutter run`)
3. Database should be accessible and migrations applied

## Test Cases

### 1. Access Forgot Password from Login Page

**Test Steps:**
1. Open the Flutter app at http://127.0.0.1:61730/
2. Verify you are on the login page
3. Look for "Forgot Password?" link below the login fields
4. Click on "Forgot Password?" link

**Expected Results:**
- App should navigate to forgot password page
- Page should display "Forgot Password?" title
- Email input field should be visible
- "Send Reset Link" button should be visible

**Actual Result:** ✅/❌ (To be filled during testing)

---

### 2. Forgot Password Page - Email Validation

**Test Steps:**
1. On the forgot password page
2. Click "Send Reset Link" without entering email
3. Enter an invalid email format (e.g., "invalid-email")
4. Click "Send Reset Link"
5. Enter a valid email format (e.g., "test@example.com")
6. Click "Send Reset Link"

**Expected Results:**
- Step 2: Should show error "Please enter your email"
- Step 4: Should show error "Please enter a valid email"
- Step 6: Should proceed without validation errors

**Actual Result:** ✅/❌ (To be filled during testing)

---

### 3. Forgot Password API Endpoint Test

**Test Steps:**
1. Open API docs at http://localhost:8000/docs
2. Navigate to POST /api/v1/auth/forgot-password
3. Try with email: "nonexistent@example.com"
4. Try with email of existing user

**Expected Results:**
- Both requests should return 200 OK
- Response message should be: "If an account with this email exists, a password reset link has been sent."
- For existing user in development mode, token should be returned

**Actual Result:** ✅/❌ (To be filled during testing)

---

### 4. Test Password Reset Flow with Backend Logs

**Test Steps:**
1. Register a test user (if not exists):
   ```bash
   curl -X POST "http://localhost:8000/api/v1/auth/register" \
   -H "Content-Type: application/json" \
   -d '{"email":"testreset@example.com","username":"testreset","password":"OriginalPassword123"}'
   ```

2. Request password reset:
   ```bash
   curl -X POST "http://localhost:8000/api/v1/auth/forgot-password" \
   -H "Content-Type: application/json" \
   -d '{"email":"testreset@example.com"}'
   ```

3. Check backend console/logs for token output
4. Copy the token from the logs
5. Test reset password with the token:
   ```bash
   curl -X POST "http://localhost:8000/api/v1/auth/reset-password" \
   -H "Content-Type: application/json" \
   -d '{"token":"<TOKEN_FROM_LOGS>","new_password":"NewSecurePassword456"}'
   ```

**Expected Results:**
- Step 1: Should return 201 with tokens
- Step 2: Should return 200 with success message
- Step 3: Token should be logged to console (development mode)
- Step 5: Should return 200 with success message
- Verify login with new password works and old password fails

**Actual Result:** ✅/❌ (To be filled during testing)

---

### 5. Test Reset Password Page Directly

**Test Steps:**
1. Get a valid token from previous test
2. Navigate to: http://127.0.0.1:61730/reset-password?token=<TOKEN>
3. Try navigating without token: http://127.0.0.1:61730/reset-password

**Expected Results:**
- Step 2: Should show reset password form
- Step 3: Should show error dialog "Invalid reset link"

**Actual Result:** ✅/❌ (To be filled during testing)

---

### 6. Password Reset Form Validation

**Test Steps:**
1. On reset password page with valid token
2. Submit without entering passwords
3. Enter password in first field only
4. Enter different passwords in both fields
5. Enter short password (< 8 characters)
6. Enter matching valid passwords (8+ chars, uppercase, lowercase, number)

**Expected Results:**
- Step 2: Should show "Please enter your new password" and "Please confirm your new password"
- Step 3: Should show "Please confirm your new password"
- Step 4: Should show "Passwords do not match"
- Step 5: Should show "Password must be at least 8 characters"
- Step 6: Should submit successfully

**Actual Result:** ✅/❌ (To be filled during testing)

---

### 7. Complete End-to-End Flow Test

**Test Steps:**
1. Register a new user
2. Logout
3. Go to login page
4. Click "Forgot Password?"
5. Enter the registered user's email
6. Note the success message
7. Get token from backend logs
8. Navigate to reset password with token
9. Enter new password
10. After success, go to login
11. Login with new password
12. Try to login with old password

**Expected Results:**
- Step 1: Registration successful
- Step 5: Shows "Email Sent!" message
- Step 8: Reset password form loads
- Step 10: Shows "Password Reset Successful!" message
- Step 11: Login successful with new password
- Step 12: Login fails with old password

**Actual Result:** ✅/❌ (To be filled during testing)

---

### 8. Edge Cases and Security Tests

**Test Steps:**
1. Try multiple reset requests for same email
2. Try using an expired token (manually modify DB)
3. Try using an already used token
4. Test with email case sensitivity (Test@Example.com vs test@example.com)

**Expected Results:**
- Step 1: Each new request should invalidate previous tokens
- Step 2: Should show "Invalid or expired reset token" error
- Step 3: Should show "Invalid or expired reset token" error
- Step 4: Should work (case insensitive)

**Actual Result:** ✅/❌ (To be filled during testing)

---

### 9. UI/UX Tests

**Test Steps:**
1. Test password visibility toggle on reset form
2. Test "Back" buttons navigation
3. Test "Resend email" functionality
4. Test loading states during API calls
5. Test error message display

**Expected Results:**
- Password should toggle between visible and hidden states
- Navigation should work correctly
- Resend should return to form and allow new submission
- Loading indicators should appear during API calls
- Errors should be displayed in user-friendly manner

**Actual Result:** ✅/❌ (To be filled during testing)

---

## Test Results Summary

### Passed Tests:
- [ ] 1. Access Forgot Password from Login
- [ ] 2. Email Validation
- [ ] 3. API Endpoint Response
- [ ] 4. Password Reset with Backend
- [ ] 5. Reset Password Page Access
- [ ] 6. Password Reset Form Validation
- [ ] 7. Complete End-to-End Flow
- [ ] 8. Edge Cases and Security
- [ ] 9. UI/UX Features

### Failed Tests:
- List any failed tests with details

### Issues Found:
1.
2.
3.

### Recommendations:
1.
2.
3.

## Additional Notes:
- The token is returned in development mode for testing purposes
- In production, the token would only be sent via email
- Password reset tokens expire after 1 hour
- All previous tokens are invalidated when a new one is requested

---

## Testing Commands Reference

### Backend Testing:
```bash
# Start backend
cd backend
uv run uvicorn app.main:app --reload

# Run specific tests
uv run pytest app/domains/user/tests/test_password_reset.py -v
uv run pytest tests/integration/test_forgot_password_complete_flow.py -v
```

### Frontend Testing:
```bash
# Run all widget tests
flutter test test/widget/

# Run specific test file
flutter test test/widget/features/auth/pages/forgot_password_page_test.dart

# Run integration tests
flutter test test/integration/test_forgot_password_flow.dart
```