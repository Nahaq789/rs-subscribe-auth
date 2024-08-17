FROM amd64/rust:1.80 as builder
WORKDIR /usr/src/rs-subscribe-auth
COPY . .
RUN cargo build --release

FROM public.ecr.aws/lambda/provided:al2023.2023.11.18.01 as rs-subscribe-auth
COPY --from=builder \
    /usr/src/rs-subscribe-auth/target/release/rs-subscribe-auth \
    ${LAMBDA_RUNTIME_DIR}/bootstrap
CMD [ "lambda-handler" ]
