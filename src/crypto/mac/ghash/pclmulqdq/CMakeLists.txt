if(ARCH_X86 OR ARCH_X86_64)
  fastd_mac_impl(ghash pclmulqdq
    ghash_pclmulqdq.c
    ghash_pclmulqdq_impl.c
    )
  fastd_mac_impl_compile_flags(ghash pclmulqdq ghash_pclmulqdq_impl.c "-mssse3 -mpclmul")

  if(WITH_MAC_GHASH_PCLMULQDQ AND NOT HAVE_PCLMUL)
    message(FATAL_ERROR "WITH_MAC_GHASH_PCLMULQDQ enabled, but there is no compiler support for -mpclmul")
  endif(WITH_MAC_GHASH_PCLMULQDQ AND NOT HAVE_PCLMUL)
endif(ARCH_X86 OR ARCH_X86_64)
