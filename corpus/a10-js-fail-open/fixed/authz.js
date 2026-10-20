async function authorize(req, res, next) {
  try {
    if (!(await policy.allows(req.user, req.path))) return res.sendStatus(403);
    next();
  } catch (e) { logger.error(e); res.sendStatus(503); }
}
