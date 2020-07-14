
# ffi shared library exposing some libff functionality.
add_library(
  ff-ffi
  SHARED

  ff_ffi.cpp
)
target_include_directories(
  ff-ffi

  PRIVATE
  ${DEPENDS_DIR}/libsnark/depends/libff
)
target_link_libraries(
  ff-ffi

  zeth
  ff
)
