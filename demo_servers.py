"""Offline demo rig: a local echo agent plus a mock Red relay.

Lets you drive the whole UI without a Red API key or an internet connection.

    .venv/bin/python demo_servers.py

  target URL : http://127.0.0.1:8801/chat   (or ws://127.0.0.1:8801/ws)
  SSE target : http://127.0.0.1:8801/sse-chat  with SSE stream URL http://127.0.0.1:8801/sse
  model API  : http://127.0.0.1:8801/v1/chat/completions  (Model API target, bearer tok-bearer-123)
  Red API URL: http://127.0.0.1:8803        (paste into the Lakera Red API URL field)
  UI tests   : http://127.0.0.1:8801/ui_tests.js
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse

from test_all import HTTP_PORT, RELAY_PORT, MockRelay, build_echo_app, serve


async def main() -> None:
    relay = MockRelay()
    relay.turns_per_session = 2
    relay_app = FastAPI()
    relay_app.include_router(relay.router())

    echo = build_echo_app()
    echo.get("/ui_tests.js")(lambda: FileResponse(Path(__file__).with_name("ui_tests.js")))
    await serve(echo, HTTP_PORT)
    await serve(relay_app, RELAY_PORT)
    print(f"echo agent : http://127.0.0.1:{HTTP_PORT}/chat  |  ws://127.0.0.1:{HTTP_PORT}/ws")
    print(f"SSE agent  : http://127.0.0.1:{HTTP_PORT}/sse-chat  +  stream "
          f"http://127.0.0.1:{HTTP_PORT}/sse")
    print(f"model API  : http://127.0.0.1:{HTTP_PORT}/v1/chat/completions")
    print(f"mock relay : http://127.0.0.1:{RELAY_PORT}")
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
