with_offload_l2tp = get_option('offload_l2tp').enabled() or (get_option('offload_l2tp').auto() and is_linux)
if not with_offload_l2tp
	subdir_done()
elif not is_linux
	error('offload_l2tp is only available on Linux')
endif

src += files(
	'l2tp.c',
)
need_libmnl = true
