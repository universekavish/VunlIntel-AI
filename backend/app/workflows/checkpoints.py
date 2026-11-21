"""Durable LangGraph PostgreSQL checkpoint integration."""

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from langgraph.checkpoint.memory import MemorySaver
from langgraph.checkpoint.postgres import PostgresSaver

from app.core.config import get_settings


@contextmanager
def postgres_checkpointer() -> Iterator[Any]:
    """Yield a setup PostgreSQL LangGraph checkpointer."""
    settings = get_settings()
    if settings.database_url.startswith("sqlite"):
        yield MemorySaver()
        return
    conn_string = settings.database_url
    if conn_string.startswith("postgresql+psycopg://"):
        conn_string = "postgresql://" + conn_string.removeprefix("postgresql+psycopg://")
    elif conn_string.startswith("postgresql+psycopg2://"):
        conn_string = "postgresql://" + conn_string.removeprefix("postgresql+psycopg2://")
    with PostgresSaver.from_conn_string(conn_string) as saver:
        saver.setup()
        yield saver
