FROM node:22-alpine
RUN --mount=type=secret,id=db_password cat /run/secrets/db_password > /dev/null
USER node
