if(ARCH_X86 OR ARCH_X86_64)
  if(NOT HAVE_PCLMUL)
    message(FATAL_ERROR "WITH_MAC_GHASH_PCLMULQDQ enabled, but there is no compiler support for -mpclmul")
  endif(NOT HAVE_PCLMUL)

  fastd_mac_impl(ghash pclmulqdq
    ghash_pclmulqdq.c
    ghash_pclmulqdq_impl.c
    )
  fastd_mac_impl_compile_flags(ghash pclmulqdq ghash_pclmulqdq_impl.c "-mssse3 -mpclmul")
endif(ARCH_X86 OR ARCH_X86_64)
