FROM eclipse-temurin:24-jdk AS build

WORKDIR /app

# Copy Maven wrapper files first
COPY .mvn .mvn
COPY mvnw ./
COPY pom.xml ./

# Make mvnw executable and download dependencies
RUN chmod +x ./mvnw
RUN ./mvnw dependency:go-offline

# Copy source code and build
COPY src ./src
RUN ./mvnw clean package -DskipTests

FROM eclipse-temurin:24-jre

WORKDIR /app

COPY --from=build /app/target/*.jar app.jar

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "/app/app.jar"]