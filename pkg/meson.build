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
	rpm_build_args = [
		rpm_build,
		'-ba',
		join_paths(meson.current_build_dir(), meson.project_name() + '.spec'),
		'--define',
		'_sourcedir ' + meson.build_root()
	]
	run_target('rpm-build', command: rpm_build_args)
	run_target('rpm-build-nvml', command: rpm_build_args + ['--with', 'nvml'])
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
			'rpm-build',
			'rpm-build-nvml'
		]
	)
endif
# }}}
# systemd, sysconfig, logrotate {{{
lockstep_fields = [
	'pid',
	'ppid',
	'start_time',
	'timestamp',
	'uptime',
	'user',
	'kernel_time',
	'userspace_time',
	'resident_set_size',
	'virtual_memory_size',
	'executable',
	'ticks_per_second',
	'read_bytes',
	'write_bytes',
	'cancelled_write_bytes',
	'in_octets',
	'out_octets',
]
lockstep_nvml_fields = [
	'nvml_utilisation',
	'nvml_memory_utilisation',
	'nvml_max_memory_usage',
	'nvml_time_ms',
]
foreach suffix : ['service', 'sysconfig', 'sysconfig.nvml', 'logrotate']
	conf = configuration_data()
	conf.set('name', meson.project_name())
	conf.set('prefix', get_option('prefix'))
	conf.set('bindir', get_option('bindir'))
	conf.set('localstatedir', get_option('localstatedir'))
	conf.set('sysconfdir', get_option('sysconfdir'))
	if suffix == 'sysconfig.nvml'
		conf.set('lockstep_fields', ','.join(lockstep_fields + lockstep_nvml_fields))
	else
		conf.set('lockstep_fields', ','.join(lockstep_fields))
	endif
	configure_file(
		input: meson.project_name() + '.' + suffix + '.in',
		output: meson.project_name() + '.' + suffix,
		configuration: conf
	)
endforeach
# }}}
