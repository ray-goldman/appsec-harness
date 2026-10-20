export function onLogin(resp) {
  localStorage.setItem('authToken', resp.token);
}
