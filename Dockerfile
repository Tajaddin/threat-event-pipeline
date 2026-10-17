# syntax=docker/dockerfile:1.7
# One Dockerfile for every service: build the reactor once, then package the module named by MODULE.
#   docker build --build-arg MODULE=detect-service -t threat/detect-service .
ARG MAVEN_IMAGE=maven:3.9.11-eclipse-temurin-21
FROM ${MAVEN_IMAGE} AS build
ARG MODULE
WORKDIR /src
COPY pom.xml ./
COPY common/pom.xml common/
COPY ingest-service/pom.xml ingest-service/
COPY enrich-service/pom.xml enrich-service/
COPY detect-service/pom.xml detect-service/
COPY index-service/pom.xml index-service/
RUN --mount=type=cache,target=/root/.m2 mvn -q -B -pl ${MODULE} -am dependency:go-offline -Dspotless.check.skip=true || true
COPY common common
COPY ${MODULE} ${MODULE}
RUN --mount=type=cache,target=/root/.m2 mvn -q -B -pl ${MODULE} -am package -DskipTests -DskipITs -Dspotless.check.skip=true -Djacoco.skip=true \
 && cp ${MODULE}/target/${MODULE}-*.jar /app.jar

FROM eclipse-temurin:25-jre-alpine AS runtime
RUN addgroup -S app && adduser -S app -G app && apk add --no-cache curl
WORKDIR /app
COPY --from=build /app.jar app.jar
USER app
ENV JAVA_TOOL_OPTIONS="-XX:MaxRAMPercentage=70 -XX:+UseG1GC -Djava.security.egd=file:/dev/./urandom"
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --start-period=60s --retries=5 CMD curl -fsS http://127.0.0.1:${SERVER_PORT:-8080}/actuator/health/liveness || exit 1
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
