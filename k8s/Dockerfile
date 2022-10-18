# For Java 11
FROM adoptopenjdk/openjdk11:alpine-jre

# Copy jar
COPY anodiam-gateway-service-*.jar /anodiam-gateway-service.jar

# Run
ENTRYPOINT ["java", "-jar","/anodiam-gateway-service.jar"]