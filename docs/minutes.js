const minutesList = document.querySelector("#minutes-list");

function createElement(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
}

function addMetaItem(list, label, value) {
  const item = createElement("div");
  item.append(createElement("dt", "", label), createElement("dd", "", value));
  list.append(item);
}

function renderMeeting(meeting) {
  const details = createElement("details", "minutes");
  details.id = `tyzden-${meeting.tyzden}`;
  details.open = meeting.tyzden === 1;

  const summary = createElement("summary");
  const toggle = createElement("span", "m-toggle", "↓");
  toggle.setAttribute("aria-hidden", "true");
  summary.append(
    createElement("span", "m-date", meeting.datum),
    createElement("span", "m-title", meeting.nazov),
    toggle
  );
  details.append(summary);

  const content = createElement("div", "m-content");
  const meta = createElement("dl", "m-meta");
  addMetaItem(meta, "Stretnutie", meeting.datum);
  addMetaItem(meta, "Zápis vypracoval", meeting.zapis_vypracoval);
  content.append(meta);

  const progress = createElement("div", "m-block");
  progress.append(
    createElement("span", "m-label", "Priebeh stretnutia"),
    createElement("p", "", meeting.priebeh_stretnutia)
  );
  content.append(progress);

  if (meeting.zadane_ulohy.length) {
    const tasks = createElement("div", "m-block");
    const taskList = createElement("ul", "m-tasks");
    tasks.append(createElement("span", "m-label", "Zadané úlohy"));
    for (const task of meeting.zadane_ulohy) {
      const item = createElement("li");
      item.append(
        createElement("span", "what", task.uloha),
        createElement("span", "who", task.zodpovedny)
      );
      taskList.append(item);
    }
    tasks.append(taskList);
    content.append(tasks);
  }

  if (meeting.pdf) {
    const pdfLink = createElement("a", "btn btn-secondary m-pdf", "Otvoriť celé PDF");
    pdfLink.href = `zapisnice/${encodeURIComponent(meeting.pdf)}`;
    pdfLink.target = "_blank";
    pdfLink.rel = "noopener";
    content.append(pdfLink);
  }

  details.append(content);
  return details;
}

async function loadMinutes() {
  const meetings = await Promise.all(
    Array.from({ length: 12 }, async (_, index) => {
      const week = String(index + 1).padStart(2, "0");
      const response = await fetch(`zapisnice/tyzden-${week}.json`);
      if (!response.ok) {
        throw new Error(`Nepodarilo sa načítať týždeň ${week}: HTTP ${response.status}`);
      }
      return response.json();
    })
  );

  for (const meeting of meetings.filter((entry) => entry.nazov)) {
    minutesList.append(renderMeeting(meeting));
  }
}

loadMinutes().catch((error) => {
  console.error(error);
  minutesList.replaceChildren(
    createElement("p", "", "Zápisnice sa nepodarilo načítať. Skúste stránku obnoviť.")
  );
});
