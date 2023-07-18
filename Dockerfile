FROM rust:1.70-slim-buster
RUN ls -a
RUN git clone -b testnet3 \
    https://github.com/medici-collective/sdk.git \
    --depth 1
RUN cargo install --path . --locked
RUN cd rust/develop
RUN cargo run --bin aleo-develop
CMD aleo-start