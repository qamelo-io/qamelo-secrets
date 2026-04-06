# Stage 1: Build
FROM maven:3.9-eclipse-temurin-25 AS build
WORKDIR /app

COPY pom.xml .
COPY qamelo-secrets-domain/pom.xml qamelo-secrets-domain/
COPY qamelo-secrets-infra/pom.xml qamelo-secrets-infra/
COPY qamelo-secrets-app/pom.xml qamelo-secrets-app/
RUN mvn dependency:go-offline -B || true

COPY . .
RUN mvn clean package -DskipTests -B

# Stage 2: JVM Runtime
FROM eclipse-temurin:25-jre-alpine
WORKDIR /app
COPY --from=build /app/qamelo-secrets-app/target/quarkus-app/ ./quarkus-app/

EXPOSE 9002
ENV JAVA_OPTS="-Djava.util.logging.manager=org.jboss.logmanager.LogManager"
ENTRYPOINT ["java", "-jar", "quarkus-app/quarkus-run.jar"]
