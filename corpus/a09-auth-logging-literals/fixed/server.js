function login(input, account) {
  const accepted = verifyCredential(input, account);
  logger.info('Authentication decision', { accountId: account.id, accepted });
  return accepted;
}
