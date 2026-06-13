from __future__ import annotations

import os
import sys

from app.core.env import load_local_env


def main() -> int:
    load_local_env()

    redis_url = os.getenv("CREDHUNTER_REDIS_URL", "redis://localhost:6379/0")
    queue_name = os.getenv("CREDHUNTER_QUEUE_NAME", "credhunter")

    try:
        from redis import Redis
        from rq import Queue, Worker
    except ImportError:
        sys.stderr.write("CredHunter-X worker requires 'redis' and 'rq' (pip install -r requirements.txt).\n")
        return 1

    connection = Redis.from_url(redis_url)
    try:
        connection.ping()
    except Exception as exc:  # Redis not reachable
        sys.stderr.write(f"CredHunter-X worker could not connect to Redis at {_redact_url(redis_url)}: {exc}\n")
        return 1

    print(
        f"CredHunter-X worker ready; redis_url={_redact_url(redis_url)}, queue={queue_name}",
        flush=True,
    )
    worker = Worker([Queue(queue_name, connection=connection)], connection=connection)
    worker.work(with_scheduler=False)
    return 0


def _redact_url(url: str) -> str:
    if "@" not in url:
        return url
    scheme, rest = url.split("://", 1)
    host = rest.split("@", 1)[1]
    return f"{scheme}://***@{host}"


if __name__ == "__main__":
    raise SystemExit(main())
