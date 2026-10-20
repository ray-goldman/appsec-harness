const name = decodeURIComponent(location.hash.slice(1));
document.getElementById('greeting').innerHTML = 'Welcome ' + name;
