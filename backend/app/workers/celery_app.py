"""Celery application shell for future background tasks."""

import os

from celery import Celery

celery_app = Celery(
    "vulnintel",
    broker=os.environ.get("REDIS_URL", "redis://redis:6379/0"),
    include=[],
)
