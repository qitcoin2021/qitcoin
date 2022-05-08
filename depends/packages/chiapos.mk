package=chiapos
$(package)_version=1.0.6
$(package)_download_path=https://github.com/Chia-Network/chiapos/archive/refs/tags/
$(package)_download_file=$($(package)_version).tar.gz
$(package)_file_name=$(package)-$($(package)_version).tar.gz
$(package)_sha256_hash=523570d82bb891e81bf0dfe3e8f06b1a54636b54718f23c2cf585aaefd283ead
$(package)_patches=001-build-as-static-library.patch 002-fix-build-mingw64.patch 003-add-apis.patch

$(package)_filesystem=gulrak_filesystem
$(package)_filesystem_version=1.5.6
$(package)_filesystem_download_path=https://github.com/gulrak/filesystem/archive/refs/tags/
$(package)_filesystem_download_file=v$($(package)_filesystem_version).tar.gz
$(package)_filesystem_file_name=$($(package)_filesystem)-$($(package)_filesystem_version).tar.gz
$(package)_filesystem_sha256_hash=16358d68f7fb1024380bc4619873b8003a5cdaa8700a0bc88ac3c6e96cbc6d48

# build options
$(package)_cmake_opts = -DTOOLCHAIN_PREFIX=$(host)
ifeq ($(host),x86_64-apple-darwin14)
$(package)_cmake_opts += -DCMAKE_C_FLAGS="$(darwin_CC_FLAGS)"
$(package)_cmake_opts += -DCMAKE_CXX_FLAGS="$(darwin_CXX_FLAGS)"
endif

define $(package)_fetch_cmds
$(call fetch_file,$(package),$($(package)_download_path),$($(package)_download_file),$($(package)_file_name),$($(package)_sha256_hash)) && \
$(call fetch_file,$(package),$($(package)_filesystem_download_path),$($(package)_filesystem_download_file),$($(package)_filesystem_file_name),$($(package)_filesystem_sha256_hash))
endef

define $(package)_preprocess_cmds
  patch -p1 < $($(package)_patch_dir)/001-build-as-static-library.patch && \
  patch -p1 < $($(package)_patch_dir)/002-fix-build-mingw64.patch && \
  patch -p1 < $($(package)_patch_dir)/003-add-apis.patch
endef

define $(package)_config_cmds
  cmake -DCMAKE_INSTALL_PREFIX=$(host_prefix) -DFETCHCONTENT_CACHE_DIR=$($(package)_source_dir) \
    $($(package)_cmake_opts)
endef

define $(package)_build_cmds
  $(MAKE) VERBOSE=1
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef
