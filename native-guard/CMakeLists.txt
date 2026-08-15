cmake_minimum_required(VERSION 3.22.1)
project(licenseguard C)

add_library(licenseguard SHARED license_guard.c)

target_compile_features(licenseguard PRIVATE c_std_11)
target_compile_options(licenseguard PRIVATE
  -O3
  -fvisibility=hidden
  -fno-ident
  -fstack-protector-strong
  -ffunction-sections
  -fdata-sections
  -Wformat
  -Werror=format-security
)
target_link_options(licenseguard PRIVATE
  -Wl,--gc-sections
  -Wl,--exclude-libs,ALL
  -Wl,-z,relro
  -Wl,-z,now
  -Wl,-z,noexecstack
)
target_link_libraries(licenseguard PRIVATE android log dl)
