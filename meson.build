project(
  'microvisor',
  version: '0.1.0',
  meson_version: '>= 1.3.0',
  license: 'MIT',
)

gnome = import('gnome')

prefix = get_option('prefix')
bindir = prefix / get_option('bindir')
libexecdir = prefix / get_option('libexecdir')
datadir = prefix / get_option('datadir')

cargo_build = custom_target(
  'cargo-build',
  output: ['microvisor', 'microvisor-helper'],
  command: [
    find_program('build-aux/cargo-build.sh'),
    meson.project_source_root(),
    meson.project_build_root(),
    get_option('buildtype'),
  ],
  build_by_default: true,
  install: true,
  install_dir: [bindir, libexecdir],
)

desktop_file = configure_file(
  input: 'data/me.nexryai.microvisor.desktop.in',
  output: 'me.nexryai.microvisor.desktop',
  copy: true,
)
install_data(desktop_file, install_dir: datadir / 'applications')

metainfo_file = configure_file(
  input: 'data/me.nexryai.microvisor.metainfo.xml.in',
  output: 'me.nexryai.microvisor.metainfo.xml',
  copy: true,
)
install_data(metainfo_file, install_dir: datadir / 'metainfo')

policy_conf = configuration_data()
policy_conf.set('LIBEXECDIR', libexecdir)
policy_file = configure_file(
  input: 'data/me.nexryai.microvisor.policy.in',
  output: 'me.nexryai.microvisor.policy',
  configuration: policy_conf,
)
install_data(policy_file, install_dir: datadir / 'polkit-1/actions')

install_data(
  'data/icons/hicolor/scalable/apps/me.nexryai.microvisor.svg',
  install_dir: datadir / 'icons/hicolor/scalable/apps',
)
install_data(
  'data/icons/hicolor/symbolic/apps/me.nexryai.microvisor-symbolic.svg',
  install_dir: datadir / 'icons/hicolor/symbolic/apps',
)

gnome.post_install(
  gtk_update_icon_cache: true,
  update_desktop_database: true,
)
