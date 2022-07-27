project(
	'lockstep',
	'c',
	version: '0.9.2',
	meson_version: '>=0.45',
	default_options: ['c_std=c11']
)

cc = meson.get_compiler('c')

foreach arg : [
    '-Werror=return-type',
    '-Werror=return-local-addr',
    '-Werror=cast-align',
    '-Wcast-align=strict',
    '-Wfloat-conversion',
    '-Werror=float-conversion',
    '-fvisibility-inlines-hidden',
]
    if cc.has_argument(arg)
        add_global_arguments(arg, language: 'c')
    endif
endforeach

if get_option('with_nvml')
	add_global_link_arguments('-lnvidia-ml', language: 'c')
endif

subdir('pkg')
subdir('src')
