# Build stage
FROM gradle:9.4-jdk21 AS build

WORKDIR /app
COPY . .

# Только сборка jar: тесты гоняются в CI, здесь они только замедляют образ.
RUN gradle bootJar --no-daemon

# Runtime stage
FROM amazoncorretto:21-alpine

WORKDIR /app
COPY --from=build /app/build/libs/*.jar app.jar

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "app.jar"]
