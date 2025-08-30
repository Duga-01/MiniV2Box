cmake_minimum_required(VERSION 3.18)
project(minivpn_mesh LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBDATACHANNEL REQUIRED libdatachannel)
find_path(NLOHMANN_JSON_INCLUDE_DIR nlohmann/json.hpp)
find_path(OLM_INCLUDE_DIR OLM/olm.hh)
find_library(OLM_LIB olm)
find_path(SODIUM_INCLUDE_DIR sodium.h)
find_library(SODIUM_LIB sodium)

include_directories(${LIBDATACHANNEL_INCLUDE_DIRS} ${NLOHMANN_JSON_INCLUDE_DIR} ${OLM_INCLUDE_DIR} ${SODIUM_INCLUDE_DIR})
link_directories(${LIBDATACHANNEL_LIBRARY_DIRS})

add_library(minivpn STATIC
        src/e2e.cpp
        src/mesh.cpp
        src/transport.cpp
        src/storage_files.cpp
)

target_include_directories(minivpn PUBLIC include)

target_link_libraries(minivpn PRIVATE ${LIBDATACHANNEL_LIBRARIES} ${OLM_LIB} ${SODIUM_LIB})

add_executable(minivpn_demo src/main.cpp)
target_link_libraries(minivpn_demo PRIVATE minivpn)
