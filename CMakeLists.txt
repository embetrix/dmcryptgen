cmake_minimum_required(VERSION 3.10)

# Set the project name
project(dmcryptgen)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Add the executable
add_executable(dmcryptgen dmcryptgen.c)

# Link the libraries
target_link_libraries(dmcryptgen ${OPENSSL_LIBRARIES})
#target_compile_options(dmcryptgen PUBLIC -Wformat -Wformat-security -Wconversion -Wsign-conversion -pedantic -Werror -Wno-deprecated-declarations)

# Specify the install rules
install(TARGETS dmcryptgen DESTINATION bin)
