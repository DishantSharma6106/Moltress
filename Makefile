SHELL := /bin/bash

.PHONY: gen build test vmtest lint proto sync-home

gen:
	cargo run -p xtask -- gen

build:
	cargo run -p xtask -- build

test:
	cargo run -p xtask -- test

vmtest:
	cargo run -p xtask -- vmtest

lint:
	cargo run -p xtask -- lint

proto:
	cargo run -p xtask -- proto

sync-home:
	cargo run -p xtask -- sync-home --dest /home/the_shant/Moltress

