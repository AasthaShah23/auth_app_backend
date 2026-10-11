from datetime import datetime

from pydantic import BaseModel, EmailStr


class UserProfileResponse(BaseModel):
    """Full user profile response for the /me endpoint."""

    id: int
    name: str
    email: EmailStr
    role: str
    is_email_verified: bool
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}
