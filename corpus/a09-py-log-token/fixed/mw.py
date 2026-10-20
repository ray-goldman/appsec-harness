import logging
log = logging.getLogger(__name__)

def before(request):
    log.info("request path=%s", request.path)
