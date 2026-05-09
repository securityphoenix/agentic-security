FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y curl
COPY . /app
CMD ["/app/run"]
