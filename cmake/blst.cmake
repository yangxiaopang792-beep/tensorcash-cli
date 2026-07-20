
if(NOT TARGET blst::blst)
  # Prefer depends/sysroot path via CMAKE_PREFIX_PATH, but also fall back to system locations.
  find_library(BLST_LIBRARY
    NAMES blst
    PATHS ${CMAKE_PREFIX_PATH} /usr/local/lib /usr/lib
    REQUIRED
  )

  find_path(BLST_INCLUDE_DIR
    NAMES blst.h
    PATHS ${CMAKE_PREFIX_PATH} /usr/local/bindings /usr/local/include /usr/include
    PATH_SUFFIXES bindings include
    REQUIRED
  )

  # Derive blst_SOURCE_DIR from include path (bindings or include parent).
  get_filename_component(blst_SOURCE_DIR "${BLST_INCLUDE_DIR}" DIRECTORY)

  add_library(blst::blst STATIC IMPORTED)
  set_target_properties(blst::blst PROPERTIES
    IMPORTED_LOCATION ${BLST_LIBRARY}
    INTERFACE_INCLUDE_DIRECTORIES ${BLST_INCLUDE_DIR}
  )

  message(STATUS "Found blst: ${BLST_LIBRARY}")
  message(STATUS "Found blst headers: ${BLST_INCLUDE_DIR}")
endif()
