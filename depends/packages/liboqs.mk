package=liboqs
# Local source lives at repo-root/shared-utils/liboqs. From depends/, that's four levels up.
$(package)_local_dir=../../../../shared-utils/liboqs
$(package)_build_subdir=build

define $(package)_set_vars
$(package)_config_opts := -DBUILD_SHARED_LIBS=OFF
$(package)_config_opts += -DOQS_BUILD_ONLY_LIB=ON
$(package)_config_opts += -DOQS_USE_OPENSSL=OFF
$(package)_config_opts += -DOQS_MINIMAL_BUILD="SIG_ml_dsa_44;SIG_ml_dsa_65;SIG_ml_dsa_87"
$(package)_config_opts += -DOQS_ENABLE_TEST_CONSTANT_TIME=ON
# Cross-compile: allow unknown/unsupported arch detection in OQS and force x86_64.
$(package)_config_opts += -DOQS_PERMIT_UNSUPPORTED_ARCHITECTURE=ON
$(package)_config_opts += -DOQS_CPU_ARCH=x86_64
endef

define $(package)_config_cmds
  $($(package)_cmake) -S .. -B .
endef

define $(package)_build_cmds
  $(MAKE)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef

define $(package)_postprocess_cmds
  rm -rf share lib/pkgconfig bin
endef
