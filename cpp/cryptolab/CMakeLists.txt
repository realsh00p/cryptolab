find_package(OpenSSL REQUIRED)
find_library(GMP_LIBRARY NAMES gmp REQUIRED)
find_library(GMPXX_LIBRARY NAMES gmpxx REQUIRED)

add_library(cryptolab_rsa
  src/rsa_diy.cpp
  src/rsa_native.cpp
)
target_include_directories(cryptolab_rsa PUBLIC include)
target_compile_features(cryptolab_rsa PUBLIC cxx_std_26)
target_link_libraries(cryptolab_rsa
  PUBLIC
    OpenSSL::Crypto
    ${GMPXX_LIBRARY}
    ${GMP_LIBRARY}
)

add_executable(cryptolab_cpp src/main.cpp)
target_link_libraries(cryptolab_cpp PRIVATE cryptolab_rsa)
