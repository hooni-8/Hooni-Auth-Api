FROM eclipse-temurin:17

COPY build/libs/*.jar /home/app.jar
ENTRYPOINT ["java","-jar","/home/app.jar"]