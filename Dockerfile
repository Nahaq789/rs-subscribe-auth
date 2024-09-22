FROM rust:1.80.1-slim-bullseye as builder
WORKDIR /app
COPY . /app
RUN apt-get update && apt-get install -y libssl-dev pkg-config
RUN cargo build --release -j 6
RUN strip /app/target/release/rs-subscribe-auth -o /rs-subscribe-auth

FROM public.ecr.aws/lambda/provided:al2023
COPY --from=public.ecr.aws/awsguru/aws-lambda-adapter:0.8.4 /lambda-adapter /opt/extensions/lambda-adapter
COPY --from=builder /rs-subscribe-auth ${LAMBDA_RUNTIME_DIR}/bootstrap
RUN dnf install -y ca-certificates

ENV RUST_LOG=info
ENV RUST_BACKTRACE=1
ENV RUSTFLAGS="-C target-cpu=native -C link-arg=-s"
ENV SSL_CERT_DIR=/etc/pki/tls/certs
ENV SSL_CERT_FILE=/etc/pki/tls/certs/ca-bundle.crt

CMD ["bootstrap"]