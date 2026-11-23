"""Schemas shared by every endpoint: error body, list meta, cursor parameters, request numbers."""

from typing import Annotated, Any, TypeVar

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    GetJsonSchemaHandler,
    SerializerFunctionWrapHandler,
    model_serializer,
)
from pydantic.json_schema import JsonSchemaValue
from pydantic_core import CoreSchema, PydanticCustomError

MAX_PAGE_SIZE = 100
DEFAULT_PAGE_SIZE = 50
BOOL_NOT_NUMBER_TYPE = "number_not_bool"  # validation error type for a JSON boolean
BOOL_NOT_NUMBER_MESSAGE = "Input should be a number, not a boolean"


def reject_bool(value: object) -> object:
    """Refuse a JSON boolean before lax number coercion reads ``true`` as 1 (rounds 53, 54)."""
    if isinstance(value, bool):
        raise PydanticCustomError(BOOL_NOT_NUMBER_TYPE, BOOL_NOT_NUMBER_MESSAGE)
    return value


_Number = TypeVar("_Number")
# A request number (``NoBool[int]``, ``NoBool[int | None]``): every numeric form accepted
# before, except ``true`` and ``false``. The check wraps the whole type, nullable included, so
# the field's ``ge``/``le`` still render as ``minimum``/``maximum`` in the published schema.
NoBool = Annotated[_Number, BeforeValidator(reject_bool)]


class RequestModel(BaseModel):
    """Base of every request body: an unknown field is a 422 naming it, never silently dropped."""

    model_config = ConfigDict(extra="forbid")


class ErrorBody(BaseModel):
    model_config = ConfigDict(frozen=True)

    code: str
    message: str
    details: dict[str, Any] = Field(default_factory=dict)
    request_id: str | None = None


class Meta(BaseModel):
    """List meta. ``note`` (round 65) is an optional human-readable warning about the answer;
    it is left out of the body entirely when there is none, so every other reply is unchanged."""

    model_config = ConfigDict(frozen=True)

    next_cursor: str | None = None
    note: str | None = None

    @classmethod
    def __get_pydantic_json_schema__(
        cls, core_schema: CoreSchema, handler: GetJsonSchemaHandler
    ) -> JsonSchemaValue:
        """Spell the fields out in OpenAPI: the wrap serializer would hide them."""
        text: JsonSchemaValue = {"anyOf": [{"type": "string"}, {"type": "null"}]}
        schema = handler.resolve_ref_schema(handler(core_schema))
        schema.clear()
        schema.update(
            {
                "properties": {
                    "next_cursor": {**text, "title": "Next Cursor"},
                    "note": {**text, "title": "Note"},
                },
                "title": "Meta",
                "type": "object",
            }
        )
        return schema

    @model_serializer(mode="wrap")
    def _drop_empty_note(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        body: dict[str, Any] = handler(self)
        if body.get("note") is None:
            body.pop("note", None)
        return body


class CursorParams(BaseModel):
    model_config = ConfigDict(frozen=True)

    cursor: str | None = None
    limit: int = Field(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE)
