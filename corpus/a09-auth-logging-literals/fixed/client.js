function refresh(response) {
  if (response.status === 401) { location.href = '/login'; return; }
}
