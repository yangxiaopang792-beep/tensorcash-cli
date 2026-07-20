package=gmp
$(package)_version=6.3.0
# Primary mirror is GNU FTP; fall back to generic GNU mirror and upstream site.
$(package)_download_path=https://ftp.gnu.org/gnu/gmp
$(package)_file_name=$(package)-$($(package)_version).tar.xz
$(package)_sha256_hash=a3c2b80201b89e68616f4ad30bc66aee4927c3ce50e33929ca819d5c43538898

define $(package)_fetch_cmds
  test -f $($(package)_source_dir)/$($(package)_file_name) || \
  ( $(call fetch_file_inner,$(package),https://ftp.gnu.org/gnu/gmp,$($(package)_file_name),$($(package)_file_name),$($(package)_sha256_hash)) || \
    $(call fetch_file_inner,$(package),https://ftpmirror.gnu.org/gmp,$($(package)_file_name),$($(package)_file_name),$($(package)_sha256_hash)) || \
    $(call fetch_file_inner,$(package),https://gmplib.org/download/gmp,$($(package)_file_name),$($(package)_file_name),$($(package)_sha256_hash)) )
endef

define $(package)_set_vars
  $(package)_config_opts=--enable-static --disable-shared --enable-cxx --with-pic
  $(package)_cflags += -fPIC
endef

define $(package)_preprocess_cmds
  cp -f $(BASEDIR)/config.guess $(BASEDIR)/config.sub .
endef

define $(package)_config_cmds
  $($(package)_autoconf)
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
