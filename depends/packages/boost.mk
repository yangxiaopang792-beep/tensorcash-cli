package=boost
$(package)_version=1.81.0
$(package)_download_path=https://archives.boost.io/release/$($(package)_version)/source/
$(package)_file_name=boost_$(subst .,_,$($(package)_version)).tar.gz
$(package)_sha256_hash=205666dea9f6a7cfed87c7a6dfbeb52a2c1b9de55712c9c1a87735d7181452b6

ifeq ($(host_os),mingw32)
ifeq ($(host_arch),x86_64)
$(package)_address_model=64
else
$(package)_address_model=32
endif

define $(package)_set_vars
  $(package)_b2_opts=variant=release
  $(package)_b2_opts+=threading=multi
  $(package)_b2_opts+=link=static
  $(package)_b2_opts+=runtime-link=static
  $(package)_b2_opts+=address-model=$($(package)_address_model)
  $(package)_b2_opts+=--layout=system
  $(package)_b2_opts+=--prefix=$($(package)_staging_prefix_dir)
  $(package)_b2_opts+=--with-locale
  $(package)_b2_opts+=boost.locale.icu=off
  $(package)_b2_opts+=target-os=windows
  $(package)_b2_opts+=binary-format=pe
  $(package)_b2_opts+=threadapi=win32
  $(package)_b2_opts+=toolset=gcc
endef

define $(package)_preprocess_cmds
  echo "using gcc : : $(host)-g++ : <rc>$(host)-windres <archiver>$(host)-ar <ranlib>$(host)-ranlib ;" > user-config.jam
endef

define $(package)_config_cmds
  ./bootstrap.sh --with-libraries=locale --without-icu --prefix=$($(package)_staging_prefix_dir)
endef

define $(package)_build_cmds
  ./b2 --user-config=user-config.jam $($(package)_b2_opts) -j$$(shell nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4) stage
endef

define $(package)_stage_cmds
  mkdir -p $($(package)_staging_prefix_dir)/lib && \
  cp -a stage/lib/* $($(package)_staging_prefix_dir)/lib/ && \
  mkdir -p $($(package)_staging_prefix_dir)/include && \
  cp -r boost $($(package)_staging_prefix_dir)/include/
endef
else
define $(package)_stage_cmds
  mkdir -p $($(package)_staging_prefix_dir)/include && \
  cp -r boost $($(package)_staging_prefix_dir)/include
endef
endif
