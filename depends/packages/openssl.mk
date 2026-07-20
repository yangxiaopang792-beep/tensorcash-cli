package=openssl
$(package)_version=3.2.1
$(package)_download_path=https://www.openssl.org/source/
$(package)_file_name=$(package)-$($(package)_version).tar.gz
$(package)_sha256_hash=83c7329fe52c850677d75e5d0b0ca245309b97e8ecbcfdc1dfdc4ab9fac35b39

$(package)_target_linux=linux-x86_64
$(package)_target_darwin=darwin64-x86_64-cc
$(package)_target_mingw32=mingw64

define $(package)_set_vars
  $(package)_config_opts=no-shared no-tests no-apps no-dso no-asm no-capieng no-winstore
  $(package)_config_opts+=--openssldir=$($(package)_staging_prefix_dir)/ssl
  $(package)_build_env+=CC="$(host_CC)"
  $(package)_build_env+=AR="$(host_AR)"
  $(package)_build_env+=RANLIB="$(host_RANLIB)"
  $(package)_build_env+=CFLAGS="$$($(package)_cppflags) $$($(package)_cflags)"
  $(package)_build_env+=LDFLAGS="$$($(package)_ldflags)"
endef

define $(package)_config_cmds
  ./Configure $($(package)_target_$(host_os)) $($(package)_config_opts) --prefix=$($(package)_staging_prefix_dir)
endef

define $(package)_build_cmds
  $(MAKE) build_libs
endef

define $(package)_stage_cmds
  $(MAKE) install_sw INSTALLTOP=$($(package)_staging_prefix_dir) OPENSSLDIR=$($(package)_staging_prefix_dir)/ssl
endef

define $(package)_postprocess_cmds
  rm -rf bin ssl misc private lib/pkgconfig share
endef
