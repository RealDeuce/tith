"use strict";

const assert = require("node:assert/strict");
const path = require("node:path");
const test = require("node:test");

class Element {
  constructor(tagName) {
    this.tagName = tagName;
    this.children = [];
    this.listeners = {};
    this.textContent = "";
    this.value = "";
    this.disabled = false;
  }

  append(...children) {
    this.children.push(...children);
  }

  replaceChildren(...children) {
    this.children = children;
  }

  addEventListener(name, listener) {
    this.listeners[name] = listener;
  }

  focus() {
    this.focused = true;
  }

  set innerHTML(value) {
    assert.equal(value, "");
    this.children = [];
  }
}

const nodes = {
  "#document-groups": new Element("div"),
  "#archive-stats": new Element("div"),
  "#document-search": new Element("input"),
  "#search-count": new Element("span"),
  "#build-note": new Element("p"),
  'a[href="#search"]': new Element("a")
};

global.document = {
  createElement: (tagName) => new Element(tagName),
  querySelector: (selector) => nodes[selector]
};
global.window = { setTimeout: (callback) => callback() };
global.fetch = async () => ({
  ok: true,
  json: async () => ({
    sourceCommit: "0123456789abcdef",
    standardsUpdatedAt: "2026-08-17T18:09:37-04:00",
    documents: [
      {
        filename: "TTS-0002.txt",
        type: "TTS",
        publication: "TTS-0002",
        revision: "1",
        title: "Type Length Value Encoding",
        date: "2026-08-16"
      },
      {
        filename: "TSP-0004.txt",
        type: "TSP",
        publication: "TSP-0004",
        revision: "2",
        title: "Local IPC Format",
        date: "2026-08-17"
      },
      {
        filename: "TRD-0001.txt",
        type: "TRD",
        publication: "TRD-0001",
        revision: "1",
        title: "FidoNet Technology Network Basics",
        date: "2026-08-16"
      }
    ]
  })
});

require(path.join(__dirname, "app.js"));

test("renders document tables from the generated archive", async () => {
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(nodes["#document-groups"].children.length, 3);
  assert.equal(nodes["#search-count"].textContent, "3 documents");
  assert.equal(
    nodes["#archive-stats"].textContent,
    "1 standards · 1 proposals · 1 references"
  );
  assert.equal(nodes["#document-search"].disabled, false);
});
