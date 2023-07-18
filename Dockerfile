FROM rust:1.70-slim-buster
RUN apt-get update -y && apt-get install git -y
RUN ls
RUN git clone -b testnet3 \
    https://github.com/medici-collective/sdk.git \
    --depth 1
WORKDIR sdk
RUN pwd
RUN ls
RUN ["chmod", "+x", "build_ubuntu.sh"]
RUN ./build_ubuntu.sh
EXPOSE 3033/tcp
EXPOSE 4133/tcp
RUN pwd
RUN cargo install --path . --locked
RUN ls
WORKDIR rust/develop
RUN pwd
CMD cargo run --bin aleo-develop && aleo-develop start
