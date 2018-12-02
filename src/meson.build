config = configuration_data()
config.set('LOCKSTEP_WITH_NVML', get_option('with_nvml'))
configure_file(
	input: 'config.h.in',
	output: 'config.h',
	configuration: config
)

executable(
	'lockstep',
	sources: ['main.c'],
	install: true
)
