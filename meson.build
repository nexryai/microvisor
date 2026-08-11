project(
  'microvisor',
  version: '0.1.0',
  meson_version: '>= 1.3.0',
  license: 'MIT',
)

prefix = get_option('prefix')
bindir = prefix / get_option('bindir')
mandir = prefix / get_option('mandir')

cargo_build = custom_target(
  'cargo-build',
  output: 'microvisor',
  command: [
    find_program('build-aux/cargo-build.sh'),
    meson.project_source_root(),
    meson.project_build_root(),
    get_option('buildtype'),
  ],
  build_by_default: true,
  install: true,
  install_dir: bindir,
)

install_man('data/microvisor.8')
install_emptydir('/etc/microvisor/profiles.d')
