async function record(evt) {
  try { await auditLog.write(evt); } catch (e) {}
}
