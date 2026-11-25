add_executable(craft_bench craft_bench.cpp)
target_link_libraries(craft_bench PRIVATE nanocraft::nanocraft nanocraft_dev_flags)
