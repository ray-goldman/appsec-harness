import logging
logger = logging.getLogger(__name__)
def authenticate(user, supplied):
    accepted = verify(user, supplied)
    logger.info("Credential decision for account %s: %s", user.id, accepted)
    return accepted
