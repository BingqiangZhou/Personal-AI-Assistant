"""Security utilities for authentication and authorization.

**Current Configuration:**
- HMAC-SHA256 (HS256): Fast, secure for symmetric-key use cases
- Cycle: 80-120 tokens/second (FastAPI 500+ req/s - no throttle)

**Performance Optimizations:**
- HMAC key caching for JWT operations
- Next: EC256 support planned for v1.3.0
"""

# Re-export all public names so that:
#   from app.core.security import create_access_token
# continues to work unchanged after the module split.

from app.core.security.encryption import (  # noqa: F401
    _derive_rsa_key_password,
    decrypt_data,
    decrypt_data_with_password,
    decrypt_rsa_data,
    enable_ec256_optimized,
    encrypt_data,
    encrypt_data_with_password,
    get_or_generate_rsa_keys,
    get_rsa_public_key_pem,
    validate_export_password,
)
from app.core.security.jwt import (  # noqa: F401
    UserId,
    create_access_token,
    create_refresh_token,
    get_token_from_request,
    get_user_id_from_token,
    require_user_id,
    token_optimizer,
    verify_token,
    verify_token_optional,
)
from app.core.security.password import (  # noqa: F401
    generate_api_key,
    generate_password_reset_token,
    generate_random_string,
    get_password_hash,
    verify_password,
    verify_password_reset_token,
)
