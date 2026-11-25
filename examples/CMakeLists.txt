foreach(e someip_to_pcapng tx_ring)
  add_executable(${e} ${e}.cpp)
  target_link_libraries(${e} PRIVATE nanocraft::nanocraft nanocraft_dev_flags)
endforeach()
