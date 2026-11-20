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

# JVM видит cgroup-лимит контейнера (mem_limit в compose).
# 40% heap от 640m ≈ 256m — с запасом для текущих ~100–160m used.
# Metaspace ограничен, чтобы Spring/Hibernate не съели всю память.
# ExitOnOutOfMemoryError — лучше рестарт контейнера, чем зависший JVM.
ENTRYPOINT ["java","-XX:MaxRAMPercentage=40","-XX:InitialRAMPercentage=15","-XX:MaxMetaspaceSize=192m","-XX:+ExitOnOutOfMemoryError","-jar","app.jar"]
