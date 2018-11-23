# RPM archive {{{
archive_name = meson.project_name() + '-' + meson.project_version()
full_archive_name = archive_name + '.tar.xz'
run_target(
	'rpm-archive',
	command: [
		'git',
		'-C',
		meson.source_root(),
		'archive',
		'-o',
		join_paths(meson.build_root(), full_archive_name),
		'--prefix',
		archive_name + '/',
		'HEAD'
	]
)
# }}}
# RPM spec {{{
rpm_spec = configuration_data()
rpm_spec.set('name', meson.project_name())
rpm_spec.set('version', meson.project_version())
rpm_spec.set('release', '1')
rpm_spec.set('archive_name', full_archive_name)
rpm_spec.set('arch', build_machine.cpu_family())
rpm_spec.set('license', ' '.join(meson.project_license()))
configure_file(
	input: meson.project_name() + '.spec.in',
	output: meson.project_name() + '.spec',
	configuration: rpm_spec
)
# }}}
# RPM build {{{
rpm_setup_tree = find_program('rpmdev-setuptree', required: false)
if not rpm_setup_tree.found()
	rpm_setup_tree = find_program('rpmsetuptree', required: false)
endif
if rpm_setup_tree.found()
	run_target('rpm-setup-tree', command: rpm_setup_tree)
endif
rpm_build = find_program('rpmbuild', required: false)
if rpm_build.found()
	run_target(
		'rpm-build',
		command: [
			rpm_build,
			'-ba',
			join_paths(meson.current_build_dir(), meson.project_name() + '.spec'),
			'--define',
			'_sourcedir ' + meson.build_root()
		]
	)
endif
# }}}
# RPM target {{{
ninja = find_program('ninja')
if ninja.found()
	run_target(
		'rpm',
		command: [
			ninja,
			'-C',
			meson.build_root(),
			'rpm-setup-tree',
			'rpm-archive',
			'rpm-build'
		]
	)
endif
# }}}
# systemd service {{{
service = configuration_data()
service.set('name', meson.project_name())
service.set('prefix', get_option('prefix'))
service.set('bindir', get_option('bindir'))
service.set('localstatedir', get_option('localstatedir'))
service.set('sysconfdir', get_option('sysconfdir'))
configure_file(
	input: meson.project_name() + '.service.in',
	output: meson.project_name() + '.service',
	configuration: service
)
# }}}
# sysconfig {{{
sysconfig = configuration_data()
configure_file(
	input: meson.project_name() + '.in',
	output: meson.project_name(),
	configuration: sysconfig
)
# }}}