FROM rust:1.70-slim-buster
RUN ls -a
RUN cargo install --path . --locked
RUN cd rust/develop
RUN cargo run --bin aleo-develop
CMD aleo-start