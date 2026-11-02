"""The upload limit must count each visitor, not the gateway in front of them."""

import asyncio
import io
import re
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
proxy_headers = pytest.importorskip("uvicorn.middleware.proxy_headers")

from bloodtrail.demo import app as demo

COMPOSE = Path(__file__).parents[2] / "docker-compose.prod.yml"
GATEWAY = "172.18.0.12"
PAST_THE_LIMIT = 400  # the route refuses this file type only after the limit lets it through
OVER_THE_LIMIT = 429


def production_setting():
    return re.search(r"^    environment:\n(?:      #.*\n)*      FORWARDED_ALLOW_IPS: (\S+)$", COMPOSE.read_text(), re.M).group(1)


def upload_status(forwarded_for):
    """Post through uvicorn's proxy handling to the real route, as the gateway would."""
    scope = {"type": "http", "client": (GATEWAY, 50000), "headers": [(b"x-forwarded-for", forwarded_for.encode())]}

    async def ignore(*_):
        pass

    async def post():
        await proxy_headers.ProxyHeadersMiddleware(ignore, production_setting())(scope, None, None)
        await demo.api_upload(demo.Request(scope), demo.UploadFile(io.BytesIO(), filename="x.txt"))

    with pytest.raises(demo.HTTPException) as refused:
        asyncio.run(post())
    return refused.value.status_code


def use_up_limit(visitor):
    assert [upload_status(visitor) for _ in range(3)] == [PAST_THE_LIMIT] * 3


@pytest.fixture(autouse=True)
def fresh_limit():
    demo._upload_times.clear()


def test_one_visitor_using_their_limit_leaves_others_free():
    use_up_limit("203.0.113.9")
    assert upload_status("198.51.100.7") == PAST_THE_LIMIT


def test_forged_forwarded_entries_do_not_buy_a_fresh_limit():
    use_up_limit("203.0.113.9")
    assert upload_status("127.0.0.1, 203.0.113.9") == OVER_THE_LIMIT
