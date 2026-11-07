# syntax=docker/dockerfile:1.7
FROM node:25-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
RUN npm run build -- --configuration production

# runs as an unprivileged user and listens on 8080
FROM nginxinc/nginx-unprivileged:1.31-alpine
COPY nginx.conf.template /etc/nginx/templates/default.conf.template
COPY --chmod=755 10-template-env.envsh /docker-entrypoint.d/10-template-env.envsh
COPY --from=build /app/dist/console/browser /usr/share/nginx/html
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --retries=3 CMD wget -qO- http://127.0.0.1:8080/ >/dev/null || exit 1
