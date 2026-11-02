FROM eclipse-temurin:17-jre-jammy
WORKDIR /app
COPY target/scala-3.3.3/register.jar /app/register.jar
COPY site /app/site
ENV PORT=8080 SITE_DIR=/app/site
EXPOSE 8080
CMD ["java", "-XX:MaxRAMPercentage=75", "-jar", "/app/register.jar"]
