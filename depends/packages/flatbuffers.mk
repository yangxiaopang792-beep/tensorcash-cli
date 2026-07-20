package=flatbuffers
$(package)_version=25.2.10
$(package)_download_path=https://github.com/google/flatbuffers/archive/refs/tags/
$(package)_file_name=v$($(package)_version).tar.gz
$(package)_sha256_hash=b9c2df49707c57a48fc0923d52b8c73beb72d675f9d44b2211e4569be40a7421

# Header-only for our use; just stage includes.
define $(package)_stage_cmds
  mkdir -p $($(package)_staging_prefix_dir)/include && \
  cp -r include/flatbuffers $($(package)_staging_prefix_dir)/include/
endef
