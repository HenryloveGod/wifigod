cmake_minimum_required(VERSION 2.6)

project(apwifi C)

if(LIB_INSTALL_DIR)
else()
  set(LIB_INSTALL_DIR lib)
endif()

add_subdirectory(src)
add_subdirectory(libhttpd)
