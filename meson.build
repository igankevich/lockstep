project(
	'lockstep',
	'c',
	version: '0.4.2',
	meson_version: '>=0.45',
	default_options: ['c_std=c11']
)

if get_option('with_nvml')
	add_global_link_arguments('-lnvidia-ml', language: 'c')
endif

subdir('pkg')
subdir('src')
