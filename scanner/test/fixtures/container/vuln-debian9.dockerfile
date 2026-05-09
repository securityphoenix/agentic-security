FROM debian:9
RUN apt-get update && apt-get install -y curl libssl-dev
WORKDIR /app
CMD ["./run"]
