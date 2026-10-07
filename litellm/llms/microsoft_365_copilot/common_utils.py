from collections.abc import Mapping
from typing import Final, cast

from pydantic import TypeAdapter, ValidationError

from litellm.llms.base_llm.chat.transformation import BaseLLMException
from litellm.types.proxy.litellm_pre_call_utils import SecretFields


class Microsoft365CopilotError(BaseLLMException):
    pass


_RAW_HEADERS_ADAPTER: Final = TypeAdapter(dict[str, str])
_SECRET_FIELDS_ADAPTER: Final = TypeAdapter(SecretFields)


def extract_caller_assertion(secret_fields: SecretFields | None) -> str | None:
    if secret_fields is None:
        return None
    secret_field_values: Final = cast(Mapping[str, object], secret_fields)
    raw_headers: Final = secret_field_values.get("raw_headers")
    try:
        headers: Final = _RAW_HEADERS_ADAPTER.validate_python(raw_headers)
    except ValidationError:
        return None
    authorization_values: Final = tuple(value for name, value in headers.items() if name.casefold() == "authorization")
    if len(authorization_values) != 1:
        return None
    authorization_parts: Final = authorization_values[0].split(maxsplit=1)
    if len(authorization_parts) != 2 or authorization_parts[0].casefold() != "bearer":
        return None
    assertion: Final = authorization_parts[1].strip()
    assertion_parts: Final = tuple(assertion.split("."))
    if (
        len(assertion_parts) != 3
        or any(not part for part in assertion_parts)
        or any(character.isspace() for character in assertion)
    ):
        return None
    return assertion


def as_secret_fields(secret_fields: object) -> SecretFields | None:
    try:
        return _SECRET_FIELDS_ADAPTER.validate_python(secret_fields)
    except ValidationError:
        return None
