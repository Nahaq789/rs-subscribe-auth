#!/bin/bash
set -euo pipefail

cargo build --release --target x86_64-unknown-linux-gnu
cp ./target/x86_64-unknown-linux-gnu/release/rs-subscribe-auth ./bootstrap
zip -j rust-lambda.zip bootstrap