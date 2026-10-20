FROM node:22.11-alpine@sha256:4f2d6f3c9f0e6b1f5f2b9b7c0c4a7a7c9d3e1f0a2b3c4d5e6f708192a3b4c5d6
WORKDIR /app
COPY package*.json ./
RUN npm ci --ignore-scripts --omit=dev
COPY . .
USER node
CMD ["node", "server.js"]
