import logging
log = logging.getLogger(__name__)

def before(request):
    log.info("auth header %s", request.headers.get("Authorization"))
