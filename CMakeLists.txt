cmake_minimum_required(3.15)

project(exports C)

add_executable(exports main.c)

enable_testing()
add_test(NAME test_exports COMMAND "$<TARGET_FILE:exports>")

