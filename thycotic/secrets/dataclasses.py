import json
import re

from dataclasses import dataclass, fields
from datetime import datetime

# Based on https://gist.github.com/jaytaylor/3660565


def to_snake_case(camel_case_dict):
    """ Transform to snake case

    Transforms the keys of the given map from camelCase to snake_case.
    """
    return [
        (
            re.compile("([a-z0-9])([A-Z])")
            .sub(r"\1_\2", re.compile(r"(.)([A-Z][a-z]+)").sub(r"\1_\2", k))
            .lower(),
            v,
        )
        for (k, v) in camel_case_dict.items()
    ]


@dataclass
class ServerSecret:
    @dataclass
    class Field:
        item_id: int
        field_id: int
        file_attachment_id: int
        field_description: str
        field_name: str
        filename: str
        value: str
        slug: str

        def __init__(self, **kwargs):
            # The REST API returns attributes with camelCase names which we
            # replace with snake_case per Python conventions
            for k, v in to_snake_case(kwargs):
                if k == "item_value":
                    k = "value"
                setattr(self, k, v)

    id: int
    folder_id: int
    secret_template_id: int
    site_id: int
    active: bool
    checked_out: bool
    check_out_enabled: bool
    name: str
    secret_template_name: str
    last_heart_beat_status: str
    last_heart_beat_check: datetime
    last_password_change_attempt: datetime
    fields: dict

    DEFAULT_DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%S"

    def __init__(self, **kwargs):
        # The REST API returns attributes with camelCase names which we replace
        # with snake_case per Python conventions
        datetime_format = self.DEFAULT_DATETIME_FORMAT
        if "datetime_format" in kwargs:
            datetime_format = kwargs["datetime_format"]
        for k, v in to_snake_case(kwargs):
            if k in ["last_heart_beat_check", "last_password_change_attempt"]:
                # @dataclass does not marshal timestamps into datetimes automatically
                v = datetime.strptime(v, datetime_format)
            setattr(self, k, v)
        self.fields = {
            item["slug"]: ServerSecret.Field(**item) for item in kwargs["items"]
        }
