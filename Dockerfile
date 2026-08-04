FROM node:24-alpine

WORKDIR /app

COPY package.json pnpm-lock.yaml ./
RUN corepack enable && pnpm install --prod --frozen-lockfile

COPY server.js db.js auth.js ./
COPY src/ ./src/

VOLUME /app/data
EXPOSE 8080

CMD ["node", "server.js"]
