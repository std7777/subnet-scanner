# Subnet Scanner

A neutral network observation and service-evidence collector. The current
command performs a one-time TCP scan of an authorized IPv4 subnet and writes
the report as JSON.

## Requirements

- Java 21 or newer
- Apache Maven 3.9 or newer

## Build and test

```shell
mvn verify
```

The executable JAR is created under `target/`.

## Run

```shell
java -jar target/subnet-scanner-0.1.0-SNAPSHOT.jar 192.168.1.0/24
```

Only scan systems and networks that you own or are authorized to test.
