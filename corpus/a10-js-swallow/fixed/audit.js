async function record(evt) {
  try { await auditLog.write(evt); } catch (e) { logger.error({ e, evt }, 'audit write failed'); throw e; }
}
