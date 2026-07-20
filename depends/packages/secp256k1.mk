package=secp256k1
# Build the shared-utils secp256k1-zkp (same as macOS/Linux jobs) to keep the
# musig2/adaptor APIs in sync across platforms.
$(package)_local_dir=../../../../shared-utils/secp256k1-zkp

define $(package)_set_vars
  $(package)_config_opts=--disable-shared --enable-static --enable-experimental
  $(package)_config_opts+=--enable-module-ecdh
  $(package)_config_opts+=--enable-module-extrakeys
  $(package)_config_opts+=--enable-module-schnorrsig
  $(package)_config_opts+=--enable-module-musig
  $(package)_config_opts+=--enable-module-ellswift
  $(package)_config_opts+=--enable-module-ecdsa-adaptor
  $(package)_config_opts+=--enable-module-recovery
  $(package)_config_opts+=--disable-tests --disable-benchmark --with-pic
endef

define $(package)_preprocess_cmds
  ./autogen.sh && \
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
  rm -rf lib/pkgconfig share bin
endef
