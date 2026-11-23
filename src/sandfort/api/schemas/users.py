"""Request/response models for ``/v1/org/members``."""

from datetime import datetime

from pydantic import BaseModel, Field, field_validator

from sandfort.api.schemas.common import RequestModel
from sandfort.api.schemas.text_checks import check_visible_text
from sandfort.domain.user import OrgRole
from sandfort.services.user_admin import Member

MAX_EMAIL_LENGTH = 320
MAX_DISPLAY_NAME_LENGTH = 255
EMAIL_PATTERN = r"^\s*[^@\s]+@[^@\s]+\.[^@\s]+\s*$"
BLANK_DISPLAY_NAME_MESSAGE = "must not be blank"


def check_display_name(value: str) -> str:
    """``value`` unchanged; a ``ValueError`` (a 422 naming the field) when nothing is visible.

    The API key name rule (no control characters, not only invisible format characters, round
    53) plus whitespace: blank, or whitespace mixed only with format characters, is refused as
    the CLI refuses it locally (round 54). Any visible script stays accepted.
    """
    if not value.strip():
        raise ValueError(BLANK_DISPLAY_NAME_MESSAGE)
    return check_visible_text(value)


class CreateMemberRequest(RequestModel):
    email: str = Field(min_length=3, max_length=MAX_EMAIL_LENGTH, pattern=EMAIL_PATTERN)
    display_name: str = Field(min_length=1, max_length=MAX_DISPLAY_NAME_LENGTH)
    role: OrgRole

    @field_validator("display_name")
    @classmethod
    def visible_display_name(cls, value: str) -> str:
        return check_display_name(value)


class UpdateMemberRequest(RequestModel):
    role: OrgRole


class MemberResponse(BaseModel):
    user_id: str
    email: str
    display_name: str
    role: OrgRole
    created_at: datetime
    disabled_at: datetime | None


def member_response(member: Member) -> MemberResponse:
    user = member.user
    return MemberResponse(
        user_id=user.id,
        email=user.email,
        display_name=user.display_name,
        role=member.role,
        created_at=user.created_at,
        disabled_at=user.disabled_at,
    )
