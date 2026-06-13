from __future__ import annotations

import os
import signal
import time

from app.core.env import load_local_env


_running = True


def main() -> int:
    load_local_env()
    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    redis_url = os.getenv("CREDHUNTER_REDIS_URL", "redis://localhost:6379/0")
    print(f"CredHunter-X worker ready; redis_url={_redact_url(redis_url)}", flush=True)

    while _running:
        time.sleep(30)

    print("CredHunter-X worker stopped.", flush=True)
    return 0


def _stop(signum, frame) -> None:
    global _running
    _running = False


def _redact_url(url: str) -> str:
    if "@" not in url:
        return url
    scheme, rest = url.split("://", 1)
    host = rest.split("@", 1)[1]
    return f"{scheme}://***@{host}"


if __name__ == "__main__":
    raise SystemExit(main())
