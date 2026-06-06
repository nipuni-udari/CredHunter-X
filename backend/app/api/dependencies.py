from __future__ import annotations

import os

from app.repositories.memory_repository import InMemoryRepository
from app.repositories.mongo_repository import MongoRepository
from app.repositories.repository import Repository

_repository: Repository | None = None


def get_repository() -> Repository:
    global _repository
    if _repository is None:
        mongodb_uri = os.getenv("CREDHUNTER_MONGODB_URI")
        if mongodb_uri:
            _repository = MongoRepository(
                uri=mongodb_uri,
                database_name=os.getenv("CREDHUNTER_MONGODB_DATABASE", "credhunter_x"),
            )
        else:
            _repository = InMemoryRepository()
    return _repository


def set_repository(repository: Repository | None) -> None:
    global _repository
    _repository = repository
