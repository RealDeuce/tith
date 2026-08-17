(() => {
  "use strict";

  const idNode = document.querySelector("#document-id");
  const titleNode = document.querySelector("#document-title");
  const metaNode = document.querySelector("#document-meta");
  const textNode = document.querySelector("#document-text");
  const rawLink = document.querySelector("#raw-link");
  const tokenPattern = /https?:\/\/[^\s<>"']+|(?:TTS|TSP|TRD|FTA|FTS|FSP|FSC)[\-‐‑‒–]\d{4}(?:\.\d{3})?/gu;
  const identifierPattern = /^(TTS|TSP|TRD|FTA|FTS|FSP|FSC)[\-‐‑‒–](\d{4})(?:\.(\d{3}))?$/u;

  function normalizedIdentifier(value) {
    return value.replace(/[‐‑‒–]/gu, "-");
  }

  function referenceTarget(value, documents) {
    if (/^https?:\/\//u.test(value)) {
      return value;
    }

    const match = identifierPattern.exec(value);
    if (!match) {
      return null;
    }
    const normalized = normalizedIdentifier(value);
    const localId = `${match[1]}-${match[2]}`;
    const local = documents.find((entry) => entry.publication === localId);
    if (local) {
      return `document.html?name=${encodeURIComponent(local.filename)}`;
    }

    if (!match[3]) {
      return null;
    }
    const archiveDirectory = match[1] === "FSP" ? "old/" : "";
    return `http://ftsc.org/docs/${archiveDirectory}${normalized.toLocaleLowerCase()}`;
  }

  function renderLinkedText(text, documents) {
    textNode.replaceChildren();
    let position = 0;
    for (const match of text.matchAll(tokenPattern)) {
      if (match.index > position) {
        textNode.append(document.createTextNode(text.slice(position, match.index)));
      }
      const value = match[0];
      const target = referenceTarget(value, documents);
      if (target) {
        const link = document.createElement("a");
        link.href = target;
        link.textContent = value;
        if (!target.startsWith("document.html")) {
          link.rel = "external noreferrer";
        }
        textNode.append(link);
      } else {
        textNode.append(document.createTextNode(value));
      }
      position = match.index + value.length;
    }
    if (position < text.length) {
      textNode.append(document.createTextNode(text.slice(position)));
    }
  }

  async function loadDocument() {
    const requested = new URLSearchParams(window.location.search).get("name");
    const archiveResponse = await fetch("standards/index.json");
    if (!archiveResponse.ok) {
      throw new Error(`archive returned ${archiveResponse.status}`);
    }
    const archive = await archiveResponse.json();
    const metadata = archive.documents.find((entry) => entry.filename === requested);
    if (!metadata) {
      throw new Error("unknown document");
    }

    const documentResponse = await fetch(`standards/${encodeURIComponent(metadata.filename)}`);
    if (!documentResponse.ok) {
      throw new Error(`document returned ${documentResponse.status}`);
    }
    const text = await documentResponse.text();

    document.title = `${metadata.publication} — ${metadata.title}`;
    idNode.textContent = metadata.publication;
    titleNode.textContent = metadata.title;
    metaNode.textContent = `Revision ${metadata.revision} · ${metadata.date}`;
    rawLink.href = `standards/${encodeURIComponent(metadata.filename)}`;
    renderLinkedText(text, archive.documents);
  }

  loadDocument().catch((error) => {
    idNode.textContent = "Error";
    titleNode.textContent = "Document unavailable";
    textNode.textContent = `The document viewer failed with uncommon precision: ${error.message}.`;
    rawLink.hidden = true;
  });
})();
