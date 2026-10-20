function validRouting(v) {
  const regexPattern = /^[0-9]{9}#$/;
  return typeof v === 'string' && v.length < 32 && regexPattern.test(v);
}
