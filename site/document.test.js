"use strict";

const assert = require("node:assert/strict");
const path = require("node:path");
const test = require("node:test");

class Element {
  constructor(tagName) {
    this.tagName = tagName;
    this.children = [];
    this.textContent = "";
    this.hidden = false;
  }

  append(...children) {
    this.children.push(...children);
  }

  replaceChildren(...children) {
    this.children = children;
  }
}

const nodes = {
  "#document-id": new Element("span"),
  "#document-title": new Element("h1"),
  "#document-meta": new Element("span"),
  "#document-text": new Element("pre"),
  "#raw-link": new Element("a")
};
const archive = {
  documents: [
    {
      filename: "TTS-0002.txt",
      publication: "TTS-0002",
      revision: "1",
      title: "Type Length Value Encoding",
      date: "2026-08-16"
    },
    {
      filename: "TTS-0005.txt",
      publication: "TTS-0005",
      revision: "3",
      title: "Bundle Format",
      date: "2026-08-17"
    }
  ]
};
const source = [
  "See TTS‑0002.",
  "See [FTA‑1006.002].",
  "See [FTS‑5000.005].",
  "See [FSP‑1016.003].",
  "See [FTS‑0001].",
  "See https://example.com/reference"
].join("\n");
let fetchCount = 0;

global.document = {
  title: "TITH Document",
  createElement: (tagName) => new Element(tagName),
  createTextNode: (textContent) => ({ nodeType: 3, textContent }),
  querySelector: (selector) => nodes[selector]
};
global.window = { location: { search: "?name=TTS-0005.txt" } };
global.fetch = async () => {
  fetchCount += 1;
  if (fetchCount === 1) {
    return { ok: true, json: async () => archive };
  }
  return { ok: true, text: async () => source };
};

require(path.join(__dirname, "document.js"));

test("links local, FTSC, and URL references in document text", async () => {
  for (let turn = 0; turn < 4; turn += 1) {
    await new Promise((resolve) => setImmediate(resolve));
  }

  assert.equal(global.document.title, "TTS-0005 — Bundle Format");
  assert.equal(nodes["#raw-link"].href, "standards/TTS-0005.txt");
  const targets = nodes["#document-text"].children
    .filter((child) => child.tagName === "a")
    .map((link) => link.href);
  assert.deepEqual(targets, [
    "document.html?name=TTS-0002.txt",
    "http://ftsc.org/docs/fta-1006.002",
    "http://ftsc.org/docs/fts-5000.005",
    "http://ftsc.org/docs/old/fsp-1016.003",
    "https://example.com/reference"
  ]);
  assert.equal(
    nodes["#document-text"].children.some(
      (child) => child.tagName === "a" && child.textContent === "FTS‑0001"
    ),
    false
  );
});
