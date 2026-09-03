from pydantic import BaseModel, Field

from app.models.user import UserRole


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str
    role: UserRole


class LoginResult(BaseModel):
    """Union-shaped login response (v2.3).

    * Password OK and no MFA required → the real access token, exactly as
      before: ``mfa_required=false`` and ``access_token`` set. Existing
      clients that read ``access_token`` keep working unchanged.
    * Password OK but MFA required → ``mfa_required=true``,
      ``access_token=null``, and ``mfa_token`` carries a 5-minute
      challenge token to POST to /api/auth/mfa/verify with the code.
    * ``enrollment_required=true`` means the account must set MFA up
      (MFA_REQUIRED is on and the user hasn't enrolled) before it can
      obtain a full token — the challenge token authorises the enrol call.
    """
    mfa_required: bool = False
    enrollment_required: bool = False
    mfa_token: str | None = None
    # Present only when no second factor is needed:
    access_token: str | None = None
    token_type: str = "bearer"
    username: str | None = None
    role: UserRole | None = None


class MfaVerifyRequest(BaseModel):
    mfa_token: str = Field(..., description="The challenge token from /api/auth/login")
    code: str = Field(..., min_length=6, max_length=12,
                      description="6-digit authenticator code, or an xxxx-xxxx backup code")
