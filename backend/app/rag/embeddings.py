"""Embedding providers with a real Sentence Transformers implementation."""

import hashlib
import math
from typing import Protocol


class EmbeddingProvider(Protocol):
    dimensions: int

    def embed_query(self, text: str) -> list[float]: ...

    def embed_documents(self, texts: list[str]) -> list[list[float]]: ...


class DeterministicHashEmbedding:
    """Offline deterministic embedding used for tests and dependency-free execution."""

    def __init__(self, dimensions: int = 384) -> None:
        if dimensions < 16 or dimensions > 4096:
            raise ValueError("Embedding dimensions must be between 16 and 4096")
        self.dimensions = dimensions

    def _embed(self, text: str) -> list[float]:
        values = [0.0] * self.dimensions
        for index, token in enumerate(text.lower().split()):
            digest = hashlib.sha256(token.encode("utf-8")).digest()
            for offset in range(0, len(digest), 4):
                position = int.from_bytes(digest[offset : offset + 4], "little") % self.dimensions
                sign = -1.0 if ((digest[offset] + index) % 2) else 1.0
                values[position] += sign
        norm = math.sqrt(sum(value * value for value in values))
        if norm == 0:
            return values
        return [value / norm for value in values]

    def embed_query(self, text: str) -> list[float]:
        return self._embed(text)

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        return [self._embed(text) for text in texts]


class SentenceTransformerEmbedding:
    """Sentence Transformers embedding provider for real application execution."""

    def __init__(self, model_name: str, dimensions: int) -> None:
        from sentence_transformers import SentenceTransformer

        self.model_name = model_name
        self.model = SentenceTransformer(model_name)
        detected = int(self.model.get_sentence_embedding_dimension())
        if detected != dimensions:
            raise ValueError(
                f"Embedding model produces {detected} dimensions, expected {dimensions}"
            )
        self.dimensions = dimensions

    def embed_query(self, text: str) -> list[float]:
        return self.model.encode(text, normalize_embeddings=True).tolist()

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        embeddings = self.model.encode(texts, normalize_embeddings=True)
        return embeddings.tolist()
