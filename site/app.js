(() => {
  "use strict";

  const groupInfo = {
    TTS: { id: "tts", title: "TITH Technical Standards" },
    TSP: { id: "tsp", title: "TITH Standards Proposals" },
    TRD: { id: "trd", title: "TITH Reference Documents" }
  };

  const groupsNode = document.querySelector("#document-groups");
  const statsNode = document.querySelector("#archive-stats");
  const searchNode = document.querySelector("#document-search");
  const countNode = document.querySelector("#search-count");
  const buildNode = document.querySelector("#build-note");
  let archive;

  function makeCell(row, text, tag = "td") {
    const cell = document.createElement(tag);
    cell.textContent = text;
    row.append(cell);
    return cell;
  }

  function renderTable(type, documents) {
    const info = groupInfo[type];
    const section = document.createElement("section");
    section.id = info.id;
    section.className = "document-group";

    const heading = document.createElement("h3");
    heading.textContent = info.title;
    section.append(heading);

    const wrap = document.createElement("div");
    wrap.className = "table-wrap";
    const table = document.createElement("table");
    const header = document.createElement("tr");
    for (const label of ["Name", "Description", "Revision", "Date"]) {
      makeCell(header, label, "th").scope = "col";
    }
    const head = document.createElement("thead");
    head.append(header);
    table.append(head);

    const body = document.createElement("tbody");
    for (const document of documents) {
      const row = document.createElement("tr");
      const nameCell = document.createElement("td");
      const link = document.createElement("a");
      link.href = `standards/${encodeURIComponent(document.filename)}`;
      link.textContent = document.publication;
      nameCell.append(link);
      row.append(nameCell);
      makeCell(row, document.title);
      makeCell(row, document.revision);
      makeCell(row, document.date);
      body.append(row);
    }
    table.append(body);
    wrap.append(table);
    section.append(wrap);
    return section;
  }

  function render(query = "") {
    const normalized = query.trim().toLocaleLowerCase();
    const matches = archive.documents.filter((document) => {
      const haystack = [
        document.publication,
        document.filename,
        document.title,
        document.revision,
        document.date
      ].join(" ").toLocaleLowerCase();
      return haystack.includes(normalized);
    });

    groupsNode.replaceChildren();
    for (const type of ["TTS", "TSP", "TRD"]) {
      const documents = matches.filter((document) => document.type === type);
      if (documents.length > 0) {
        groupsNode.append(renderTable(type, documents));
      }
    }
    if (matches.length === 0) {
      const empty = document.createElement("p");
      empty.className = "empty-result";
      empty.textContent = "No committee document matches that remarkably specific request.";
      groupsNode.append(empty);
    }

    countNode.textContent = normalized
      ? `${matches.length} of ${archive.documents.length} documents`
      : `${archive.documents.length} documents`;
  }

  function formatDate(value) {
    const date = new Date(value);
    return Number.isNaN(date.valueOf())
      ? value
      : new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(date);
  }

  fetch("standards/index.json")
    .then((response) => {
      if (!response.ok) {
        throw new Error(`archive returned ${response.status}`);
      }
      return response.json();
    })
    .then((data) => {
      archive = data;
      const counts = data.documents.reduce((totals, document) => {
        totals[document.type] = (totals[document.type] || 0) + 1;
        return totals;
      }, {});
      statsNode.textContent = `${counts.TTS || 0} standards · ${counts.TSP || 0} proposals · ${counts.TRD || 0} references`;
      const shortCommit = data.sourceCommit.slice(0, 8);
      buildNode.textContent = `Standards last changed ${formatDate(data.standardsUpdatedAt)} · source ${shortCommit}`;
      render();
    })
    .catch((error) => {
      groupsNode.innerHTML = "";
      const notice = document.createElement("p");
      notice.className = "notice";
      notice.textContent = `The automatic index failed with uncommon precision: ${error.message}.`;
      groupsNode.append(notice);
      statsNode.textContent = "Index unavailable";
      searchNode.disabled = true;
    });

  searchNode.addEventListener("input", () => {
    if (archive) {
      render(searchNode.value);
    }
  });

  document.querySelector('a[href="#search"]').addEventListener("click", () => {
    window.setTimeout(() => searchNode.focus(), 0);
  });
})();
