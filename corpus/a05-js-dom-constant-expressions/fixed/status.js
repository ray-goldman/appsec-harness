function renderStatus(panel, ready) {
  panel.innerHTML = `<span class="status">${ready ? "Ready" : "Waiting"}</span>`;
}
