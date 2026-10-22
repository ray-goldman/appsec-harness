function renderStatus(panel, ready) {
  panel.innerHTML = `<span class="status">${ready ? location.hash : "Waiting"}</span>`;
}
