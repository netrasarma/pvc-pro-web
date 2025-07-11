# This is a special Dockerfile for debugging file structure
FROM alpine:latest
WORKDIR /workspace
COPY . .
CMD ["ls", "-R"]
