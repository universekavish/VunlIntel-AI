"""Prepare source records as traceable LangChain documents."""

from dataclasses import dataclass
from typing import Any

from langchain_core.documents import Document
from langchain_text_splitters import RecursiveCharacterTextSplitter


@dataclass(frozen=True, slots=True)
class PreparedChunk:
    source: str
    source_id: str
    document_type: str
    chunk_index: int
    text: str
    metadata: dict[str, Any]


def prepare_document(
    *,
    source: str,
    source_id: str,
    document_type: str,
    text: str,
    metadata: dict[str, Any] | None = None,
    chunk_size: int = 1200,
    chunk_overlap: int = 150,
) -> list[PreparedChunk]:
    """Split external source text into bounded, cited LangChain documents."""
    cleaned = "\n".join(line.strip() for line in text.strip().splitlines() if line.strip())
    if not cleaned:
        return []
    splitter = RecursiveCharacterTextSplitter(
        chunk_size=chunk_size,
        chunk_overlap=chunk_overlap,
        separators=["\n\n", "\n", ". ", " ", ""],
    )
    chunks = splitter.split_text(cleaned)
    base = dict(metadata or {})
    base.update(
        {
            "source": source,
            "source_id": source_id,
            "document_type": document_type,
            "citation": f"{source}:{source_id}",
        }
    )
    return [
        PreparedChunk(
            source=source,
            source_id=source_id,
            document_type=document_type,
            chunk_index=index,
            text=chunk,
            metadata={**base, "chunk_index": index},
        )
        for index, chunk in enumerate(chunks)
    ]


def langchain_document(chunk: PreparedChunk) -> Document:
    """Convert an internal chunk to LangChain's typed Document contract."""
    return Document(page_content=chunk.text, metadata=dict(chunk.metadata))


def cve_document(
    cve_id: str, description: str | None, payload: dict[str, Any]
) -> list[PreparedChunk]:
    cvss = payload.get("cvss")
    text = (
        f"CVE identifier: {cve_id}\n"
        f"Description: {description or 'No description available.'}\n"
        f"CVSS data: {cvss if cvss else 'No CVSS metric recorded.'}\n"
        f"CWE identifiers: {', '.join(payload.get('cwe_ids', []) or []) or 'None recorded.'}\n"
        f"References: {', '.join(payload.get('references', []) or []) or 'None recorded.'}"
    )
    return prepare_document(
        source="nvd",
        source_id=cve_id,
        document_type="cve",
        text=text,
        metadata={"cve_id": cve_id},
    )


def kev_document(payload: dict[str, Any]) -> list[PreparedChunk]:
    cve_id = str(payload["cve_id"])
    text = (
        f"CVE identifier: {cve_id}\n"
        f"Vendor: {payload.get('vendor_project') or 'Unknown'}\n"
        f"Product: {payload.get('product') or 'Unknown'}\n"
        f"Name: {payload.get('name') or 'Unknown'}\n"
        f"Ransomware indicator: {payload.get('known_ransomware') or 'Unknown'}\n"
        f"Required action context: {payload.get('notes') or 'No notes recorded.'}"
    )
    return prepare_document(
        source="cisa_kev",
        source_id=cve_id,
        document_type="kev",
        text=text,
        metadata={"cve_id": cve_id},
    )


def cwe_document(payload: dict[str, Any]) -> list[PreparedChunk]:
    cwe_id = str(payload["cwe_id"])
    text = (
        f"CWE identifier: {cwe_id}\n"
        f"Name: {payload.get('name') or 'Unknown'}\n"
        f"Abstract: {payload.get('weakness_abstract') or 'Unknown'}\n"
        f"Description: {payload.get('description') or 'No description recorded.'}"
    )
    return prepare_document(
        source="mitre_cwe",
        source_id=cwe_id,
        document_type="cwe",
        text=text,
        metadata={"cwe_id": cwe_id},
    )


def osv_document(payload: dict[str, Any]) -> list[PreparedChunk]:
    osv_id = str(payload["osv_id"])
    text = (
        f"OSV identifier: {osv_id}\n"
        f"Aliases: {', '.join(payload.get('aliases', []) or []) or 'None recorded.'}\n"
        f"Summary: {payload.get('summary') or 'No summary recorded.'}\n"
        f"Details: {payload.get('details') or 'No details recorded.'}\n"
        f"References: {', '.join(payload.get('references', []) or []) or 'None recorded.'}"
    )
    return prepare_document(
        source="osv",
        source_id=osv_id,
        document_type="osv",
        text=text,
        metadata={"osv_id": osv_id, "aliases": payload.get("aliases", [])},
    )


def advisory_document(
    *,
    source_id: str,
    payload: dict[str, Any],
) -> list[PreparedChunk]:
    title = payload.get("title") or payload.get("name") or source_id
    body = payload.get("description") or payload.get("details") or payload.get("summary")
    references = payload.get("references")
    references_text = (
        references
        if isinstance(references, str)
        else " ".join(str(item) for item in references or [])
    )
    text = (
        f"Vendor advisory: {title}\n"
        f"Identifier: {source_id}\n"
        f"Details: {body or 'No advisory details recorded.'}\n"
        f"References: {references_text}"
    )
    return prepare_document(
        source="vendor_advisory",
        source_id=source_id,
        document_type="vendor_advisory",
        text=text,
        metadata={"title": title, "advisory_id": source_id},
    )
