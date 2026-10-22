from flask import request
import logging
logger = logging.getLogger(__name__)
logger.info("Account password changed from %s", request.form["password"])
