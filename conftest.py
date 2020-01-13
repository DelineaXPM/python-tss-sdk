import json
import pytest


@pytest.fixture
def server_json():
    with open("test_server.json") as f:
        return json.load(f)
