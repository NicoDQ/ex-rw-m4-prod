# =============================
# Etapa 1: Construcción del JAR
# =============================
FROM maven:3.9-eclipse-temurin-21 AS build

# Establecemos el directorio de trabajo
WORKDIR /app

# Copiamos el pom.xml y descargamos dependencias
COPY pom.xml .
RUN mvn dependency:go-offline

# Copiamos el resto del código fuente
COPY src ./src

# Compilamos el proyecto y generamos el JAR
RUN mvn clean package -DskipTests

# =============================
# Etapa 2: Imagen final (runtime)
# =============================
FROM openjdk:21-slim

# Variables de entorno opcionales por defecto (Render las puede sobreescribir)
#ENV SPRING_DATASOURCE_URL=jdbc:postgresql://localhost:5432/products
#ENV SPRING_DATASOURCE_USERNAME=authuser
#ENV SPRING_DATASOURCE_PASSWORD=authpass
#ENV SPRING_JPA_HIBERNATE_DDL_AUTO=update
#ENV SPRING_JPA_SHOW_SQL=true
#ENV JWT_SECRET=111111222333334r444

# Crea un directorio de trabajo en el contenedor
WORKDIR /app

# Copia el JAR desde la imagen de construcción
COPY --from=build /app/target/*.jar app.jar

# Exponemos el puerto por defecto de Spring Boot
EXPOSE 8080

# Ejecutamos la aplicación
ENTRYPOINT ["java", "-jar", "app.jar"]
