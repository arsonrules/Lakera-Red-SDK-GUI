"""Offline demo rig: a local echo agent plus a mock Red relay.

Lets you drive the whole UI without a Red API key or an internet connection.

    .venv/bin/python demo_servers.py

  target URL : http://127.0.0.1:8801/chat   (or ws://127.0.0.1:8801/ws)
  SSE target : http://127.0.0.1:8801/sse-chat  with SSE stream URL http://127.0.0.1:8801/sse
  Red API URL: http://127.0.0.1:8803        (paste into the Lakera Red API URL field)
"""

from __future__ import annotations

import asyncio
import json

from fastapi import FastAPI, Request, Response

from test_all import HTTP_PORT, RELAY_PORT, MockRelay, build_echo_app, serve


async def main() -> None:
    relay = MockRelay()
    relay.turns_per_session = 2
    relay_app = FastAPI()
    relay_app.include_router(relay.router())

    @relay_app.middleware("http")
    async def gate(request: Request, call_next):
        response = await call_next(request)
        if request.url.path == "/relay/messages" and response.status_code == 200:
            body = b"".join([chunk async for chunk in response.body_iterator])
            data = json.loads(body)
            if data.get("sessionId") and not data.get("type"):
                relay.pending.setdefault(data["sessionId"], {})["awaiting"] = True
            response = Response(body, response.status_code, dict(response.headers),
                                response.media_type)
        return response

    await serve(build_echo_app(), HTTP_PORT)
    await serve(relay_app, RELAY_PORT)
    print(f"echo agent : http://127.0.0.1:{HTTP_PORT}/chat  |  ws://127.0.0.1:{HTTP_PORT}/ws")
    print(f"SSE agent  : http://127.0.0.1:{HTTP_PORT}/sse-chat  +  stream "
          f"http://127.0.0.1:{HTTP_PORT}/sse")
    print(f"mock relay : http://127.0.0.1:{RELAY_PORT}")
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
