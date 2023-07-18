FROM rust:1.70-slim-buster
RUN apt-get update -y && apt-get install git -y
RUN git clone -b testnet3 \
    https://github.com/medici-collective/sdk.git \
    --depth 1
WORKDIR sdk
RUN pwd
RUN cargo install --path . --locked
# RUN cd rust/develop
RUN pwd
RUN cargo run --bin aleo-develop
CMD aleo-start