# DetectAI dashboard — multi-stage build: compile with Node, serve the
# static output with nginx running as a non-root user.
#
# NOTE: same caveat as backend/Dockerfile — written carefully but not
# built/run in the environment that produced it. Test before relying on it:
#   docker build -t detectai-frontend .
#   docker run --rm -p 8080:8080 detectai-frontend

FROM node:22-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .

# Vite inlines VITE_* env vars at BUILD time, not runtime — so this must
# be a build arg, not a docker-compose `environment:` entry (which would
# have no effect on the already-built static files).
ARG VITE_API_BASE_URL=http://localhost:8000/api/v1
ENV VITE_API_BASE_URL=$VITE_API_BASE_URL

RUN npm run build

FROM nginxinc/nginx-unprivileged:1.27-alpine AS runtime
# nginx-unprivileged already runs as a non-root user (uid 101) and listens
# on port 8080 instead of 80, avoiding the need for root to bind <1024.
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/ || exit 1
