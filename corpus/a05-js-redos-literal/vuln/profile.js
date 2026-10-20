function validRouting(v) {
  const regexPattern = /([0-9]+)+\#/;
  return regexPattern.test(v);
}
