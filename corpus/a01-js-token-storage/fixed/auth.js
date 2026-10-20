export function onLogin(resp) {
  // session cookie is HttpOnly; nothing to store client-side
  return resp.ok;
}
