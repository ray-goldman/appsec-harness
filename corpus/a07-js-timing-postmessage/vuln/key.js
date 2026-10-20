function checkKey(req, apiKey) {
  return apiKey === req.headers['x-api-key'];
}
