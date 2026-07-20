package=blst
$(package)_version=0.3.11
$(package)_download_path=https://github.com/supranational/blst/archive/refs/tags/
$(package)_file_name=v$($(package)_version).tar.gz
$(package)_sha256_hash=d0a6e2a69490cc45f0a531a684a225e56fe22303665157cfa397ba5605447eb9

define $(package)_set_vars
  # Respect depends toolchain for cross builds.
  $(package)_build_env+=CC="$(host_CC)"
  $(package)_build_env+=AR="$(host_AR)"
  $(package)_build_env+=CFLAGS="$$($(package)_cppflags) $$($(package)_cflags)"
endef

define $(package)_build_cmds
  ./build.sh -O3 $(if $(filter mingw32,$(host_os)),flavour=mingw64,)
endef

define $(package)_stage_cmds
  mkdir -p $($(package)_staging_prefix_dir)/lib && \
  cp libblst.a $($(package)_staging_prefix_dir)/lib/ && \
  mkdir -p $($(package)_staging_prefix_dir)/bindings && \
  cp bindings/*.h $($(package)_staging_prefix_dir)/bindings/
endef

define $(package)_postprocess_cmds
  rm -f libblst.dll
endef
