package=cppzmq
$(package)_version=4.9.0
$(package)_download_path=https://github.com/zeromq/cppzmq/archive/refs/tags/
$(package)_file_name=v$($(package)_version).tar.gz
$(package)_sha256_hash=3fdf5b100206953f674c94d40599bdb3ea255244dcc42fab0d75855ee3645581

define $(package)_stage_cmds
  mkdir -p $($(package)_staging_prefix_dir)/include && \
  cp -r zmq.hpp zmq_addon.hpp $($(package)_staging_prefix_dir)/include/ && \
  if [ -d cmake ]; then \
    mkdir -p $($(package)_staging_prefix_dir)/cmake; \
    cp -r cmake/* $($(package)_staging_prefix_dir)/cmake/; \
  fi
endef
