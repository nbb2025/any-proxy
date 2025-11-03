# syntax=docker/dockerfile:1.6

FROM node:20-alpine AS deps
WORKDIR /app
RUN corepack enable pnpm
COPY frontend/package.json frontend/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile

FROM node:20-alpine AS builder
WORKDIR /app
RUN corepack enable pnpm
COPY --from=deps /app/node_modules ./node_modules
COPY frontend ./

ARG NEXT_PUBLIC_CONTROL_PLANE_URL=http://localhost:8080
ENV NEXT_PUBLIC_CONTROL_PLANE_URL=$NEXT_PUBLIC_CONTROL_PLANE_URL

RUN pnpm build

FROM node:20-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production

RUN corepack enable pnpm

COPY --from=builder /app/public ./public
COPY --from=builder /app/.next ./.next
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./package.json

EXPOSE 3000

ENV PORT=3000

CMD ["pnpm", "start"]
