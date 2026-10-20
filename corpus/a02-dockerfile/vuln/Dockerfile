FROM node:latest
WORKDIR /app
RUN curl -fsSL https://get.example.sh/install | sh
COPY . .
RUN npm install
CMD ["node", "server.js"]
