if not get_option('build_tests')
	subdir_done()
endif

cmocka_dep = dependency('cmocka')

test_deps = declare_dependency(
	include_directories: srcdir,
	link_whole: libfastd,
	dependencies: cmocka_dep,
)
test_env = ['CMOCKA_MESSAGE_OUTPUT=TAP']

test_uhash = executable(
	'test-uhash', 'test-uhash.c',
	dependencies: test_deps,
)
test('uhash',
	test_uhash,
	env : test_env,
	protocol : 'tap',
)
