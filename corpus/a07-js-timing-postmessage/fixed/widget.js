const TRUSTED = 'https://app.example.com';
window.addEventListener('message', (event) => {
  if (event.origin !== TRUSTED) return;
  runCommand(event.data);
});
