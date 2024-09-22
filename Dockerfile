FROM rust:1.80-slim-bullseye as base

FROM base as builder
WORKDIR /app
COPY . /app
RUN cargo build --release -j 6 --no-default-features
RUN strip /app/target/release/rs-subscribe-auth -o /rs-subscribe-auth

FROM gcr.io/distroless/cc
COPY --from=public.ecr.aws/awsguru/aws-lambda-adapter:0.7.1 /lambda-adapter /opt/extensions/lambda-adapter
COPY --from=builder /rs-subscribe-auth ${LAMBDA_RUNTIME_DIR}/bootstrap

ENV RUST_LOG=info
ENV RUST_BACKTRACE=1
ENV RUSTFLAGS="-C target-cpu=native -C link-arg=-s"

EXPOSE 8080
CMD [ "/rs-subscribe-auth" ]