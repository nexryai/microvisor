SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.ONESHELL:

repo := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/..)
outdir ?= $(CURDIR)
spec ?= $(repo)/microvisor.spec

.PHONY: srpm
srpm:
	# COPR runs make_srpm in a disposable buildroot. Local non-root builds must provide these tools.
	if (( EUID == 0 )); then
		dnf -y install cargo cargo-rpm-macros git-core rpm-build tar xz
	fi
	for tool in cargo git rpmbuild rpmspec tar xz; do
		command -v "$$tool" >/dev/null || {
			echo "Required SRPM tool is missing: $$tool" >&2
			exit 1
		}
	done

	spec_path="$$(realpath "$(spec)")"
	output_directory="$$(realpath -m "$(outdir)")"
	mkdir -p "$$output_directory"
	work="$$(mktemp -d)"
	trap 'rm -rf -- "$$work"' EXIT

	name="$$(rpmspec -q --srpm --qf '%{NAME}\n' "$$spec_path")"
	version="$$(rpmspec -q --srpm --qf '%{VERSION}\n' "$$spec_path")"
	epoch="$$(git -C "$(repo)" log -1 --format=%ct)"
	source_archive="$$work/$$name-$$version.tar.xz"
	vendor_archive="$$work/$$name-$$version-vendor.tar.xz"

	git -C "$(repo)" archive \
		--format=tar \
		--prefix="$$name-$$version/" \
		HEAD | xz --threads=1 -9 --stdout >"$$source_archive"
	cargo vendor \
		--manifest-path "$(repo)/Cargo.toml" \
		--locked \
		--versioned-dirs \
		"$$work/vendor" >/dev/null
	tar \
		--sort=name \
		--mtime="@$$epoch" \
		--owner=0 \
		--group=0 \
		--numeric-owner \
		-C "$$work" \
		-cf - vendor | xz --threads=1 -9 --stdout >"$$vendor_archive"

	mkdir -p \
		"$$work/rpmbuild/BUILD" \
		"$$work/rpmbuild/BUILDROOT" \
		"$$work/rpmbuild/RPMS" \
		"$$work/rpmbuild/SOURCES" \
		"$$work/rpmbuild/SPECS" \
		"$$work/rpmbuild/SRPMS" \
		"$$work/srpm"
	rpmbuild -bs "$$spec_path" \
		--define "_topdir $$work/rpmbuild" \
		--define "_sourcedir $$work" \
		--define "_srcrpmdir $$work/srpm"
	shopt -s nullglob
	srpms=("$$work"/srpm/*.src.rpm)
	if (( $${#srpms[@]} != 1 )); then
		echo "Expected exactly one SRPM, found $${#srpms[@]}" >&2
		exit 1
	fi
	install -m 0644 "$${srpms[0]}" "$$output_directory/"
	echo "Created $$output_directory/$$(basename "$${srpms[0]}")"
