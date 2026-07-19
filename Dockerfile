FROM oven/bun:1

WORKDIR /app

COPY package.json bun.lockb ./
RUN bun install --frozen-lockfile

EXPOSE 5885

CMD ["bun", "run", "dev"]
