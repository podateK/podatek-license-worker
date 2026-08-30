# --- build stage ---
FROM gradle:8.10-jdk17 AS build
WORKDIR /app
COPY . .
RUN gradle --no-daemon shadowJar

# --- runtime stage ---
FROM eclipse-temurin:17-jre
WORKDIR /app
COPY --from=build /app/build/libs/*-all.jar app.jar
ENV PORT=8080
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://localhost:8080/healthz || exit 1
CMD ["java","-jar","app.jar"]
