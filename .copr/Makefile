SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.ONESHELL:

.PHONY: srpm

srpm:
	missing=0
	for command in cargo git rpmbuild tar xz; do
		command -v "$$command" >/dev/null 2>&1 || missing=1
	done
	if (( missing )); then
		dnf -y install cargo git rpm-build tar xz
	fi

	project_dir="$$(pwd)"
	output_dir="$$(readlink -m "$${outdir:-$$project_dir}")"
	spec_file="$${spec:-$$project_dir/microvisor.spec}"
	version="$$(sed -n 's/^version = "\([^"]*\)"$$/\1/p' Cargo.toml | head -n 1)"
	test -n "$$version"
	test -f "$$spec_file"
	mkdir -p "$$output_dir"

	temp_dir="$$(mktemp -d)"
	trap 'rm -rf "$$temp_dir"' EXIT
	archive_root="microvisor-$$version"
	source_date_epoch="$$(git log -1 --format=%ct 2>/dev/null || date +%s)"

	if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
		git archive \
			--format=tar \
			--prefix="$$archive_root/" \
			HEAD > "$$temp_dir/source.tar"
	else
		mkdir -p "$$temp_dir/$$archive_root"
		tar \
			--exclude=.git \
			--exclude=build \
			--exclude=target \
			--exclude='*.src.rpm' \
			--exclude='*.tar.xz' \
			-cf - . | tar -xf - -C "$$temp_dir/$$archive_root"
		tar -C "$$temp_dir" -cf "$$temp_dir/source.tar" "$$archive_root"
	fi
	xz -T0 -9 "$$temp_dir/source.tar"
	mv "$$temp_dir/source.tar.xz" \
		"$$output_dir/microvisor-$$version.tar.xz"

	cargo vendor \
		--locked \
		--versioned-dirs \
		"$$temp_dir/vendor" >/dev/null
	tar \
		--sort=name \
		--mtime="@$$source_date_epoch" \
		--owner=0 \
		--group=0 \
		--numeric-owner \
		-C "$$temp_dir" \
		-cJf "$$output_dir/microvisor-$$version-vendor.tar.xz" \
		vendor

	rpmbuild -bs "$$spec_file" \
		--define "_sourcedir $$output_dir" \
		--define "_srcrpmdir $$output_dir"
