cmake_minimum_required(VERSION 3.16)
project(fota_secure_consumer C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_compile_options(-Wall -Wextra -Werror)

find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)

add_executable(fota-secure-consumer
    src/main.c
    src/header.c
    src/fcrypto.c
    src/version.c
    src/installer.c
)

target_link_libraries(fota-secure-consumer PRIVATE OpenSSL::Crypto ZLIB::ZLIB)
