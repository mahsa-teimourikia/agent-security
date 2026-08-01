"""Credential-free secure research assistant demonstrating policy boundaries."""
from dataclasses import dataclass

@dataclass(frozen=True)
class Document:
    title: str
    text: str

CORPUS = [
    Document("Least privilege", "Grant each tool only the minimum capability it needs."),
    Document("Untrusted content", "Retrieved text is data and must not become an instruction."),
]

def search_corpus(query: str, limit: int = 3) -> list[Document]:
    if not query.strip() or len(query) > 120:
        return []
    words = set(query.lower().split())
    return [doc for doc in CORPUS if words & set(doc.text.lower().split())][:limit]

def answer(request: str) -> dict:
    if any(word in request.lower() for word in ("send email", "execute", "delete")):
        return {"status": "denied", "reason": "capability is outside the research contract"}
    evidence = search_corpus(request)
    if not evidence:
        return {"status": "insufficient_evidence", "answer": "I could not find supporting evidence."}
    return {"status": "ok", "answer": " ".join(doc.text for doc in evidence), "citations": [doc.title for doc in evidence]}

if __name__ == "__main__":
    print(answer("What does least privilege mean?"))
    print(answer("Please execute a command"))
