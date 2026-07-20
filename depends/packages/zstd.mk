package=zstd
$(package)_version=1.5.6
$(package)_download_path=https://github.com/facebook/zstd/releases/download/v$($(package)_version)/
$(package)_file_name=$(package)-$($(package)_version).tar.gz
$(package)_sha256_hash=8c29e06cf42aacc1eafc4077ae2ec6c6fcb96a626157e0593d5e82a34fd403c1
$(package)_build_subdir=cmake-build

define $(package)_set_vars
$(package)_config_opts := -DZSTD_BUILD_TESTS=OFF -DZSTD_BUILD_PROGRAMS=OFF -DZSTD_BUILD_SHARED=OFF
$(package)_config_opts += -DZSTD_BUILD_STATIC=ON -DZSTD_LEGACY_SUPPORT=OFF -DZSTD_BUILD_CONTRIB=OFF
$(package)_config_opts += -DCMAKE_POSITION_INDEPENDENT_CODE=ON
endef

define $(package)_config_cmds
  $($(package)_cmake) -S ../build/cmake -B .
endef

define $(package)_build_cmds
  $(MAKE)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef

define $(package)_postprocess_cmds
  rm -rf bin share lib/pkgconfig
endef
