FROM rust:1.80-slim-bullseye as base

FROM base as builder
WORKDIR /app
COPY . /app
RUN cargo build --release
RUN strip /app/target/release/rs-subscribe-auth -o /rs-subscribe-auth

FROM gcr.io/distroless/cc
COPY --from=public.ecr.aws/awsguru/aws-lambda-adapter:0.7.1 /lambda-adapter /opt/extensions/lambda-adapter
COPY --from=builder /rs-subscribe-auth /
EXPOSE 8080
CMD [ "/rs-subscribe-auth" ]