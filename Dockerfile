FROM node:22-slim

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY src/ ./src/

USER node

ENTRYPOINT ["node", "src/cli/index.js"]
CMD ["--help"]
