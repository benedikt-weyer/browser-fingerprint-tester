FROM node:22-alpine

WORKDIR /app

COPY package.json pnpm-lock.yaml ./
RUN corepack enable && pnpm install --prod --frozen-lockfile

COPY server.js ./
COPY src/ ./src/

EXPOSE 8080

CMD ["node", "server.js"]
