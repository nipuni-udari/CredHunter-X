from __future__ import annotations

import os

from app.repositories.memory_repository import InMemoryRepository
from app.repositories.mongo_repository import MongoRepository
from app.repositories.repository import Repository


def build_repository() -> Repository:
    """Build a repository from environment configuration.

    Uses MongoDB when CREDHUNTER_MONGODB_URI is set, otherwise an in-memory
    repository. Shared by the API process and the background worker so they
    can read and write the same storage backend.
    """

    mongodb_uri = os.getenv("CREDHUNTER_MONGODB_URI")
    if mongodb_uri:
        return MongoRepository(
            uri=mongodb_uri,
            database_name=os.getenv("CREDHUNTER_MONGODB_DATABASE", "credhunter_x"),
        )
    return InMemoryRepository()
