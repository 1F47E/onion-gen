ARGS ?=

build:
	cargo build --release

run:
	cargo run --release -- $(ARGS)

lint:
	cargo clippy -- -D warnings

test:
	cargo test

clean:
	cargo clean

.PHONY: build run lint test clean
