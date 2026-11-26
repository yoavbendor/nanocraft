set(_nanocraft_tests test_checksum test_template test_segment test_nanowire test_pcap test_replay test_linux_tx)
foreach(t ${_nanocraft_tests})
  add_executable(${t} ${t}.cpp)
  # nanom::shark: an independent pcap/pcapng scanner (oracle for the writers).
  target_link_libraries(${t} PRIVATE nanocraft::nanocraft nanom::shark nanocraft_dev_flags)
  add_test(NAME ${t} COMMAND ${t} ${CMAKE_CURRENT_BINARY_DIR})
  set_tests_properties(${t} PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 300)
endforeach()

# Independent third-party readers (python dpkt + scapy) over the files test_pcap / test_nanowire write. Skipped
# (77) when python or the modules are missing.
find_package(Python3 COMPONENTS Interpreter)
if(Python3_Interpreter_FOUND)
  add_test(NAME python_oracle
           COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/python_oracle.py ${CMAKE_CURRENT_BINARY_DIR})
  set_tests_properties(python_oracle PROPERTIES SKIP_RETURN_CODE 77 DEPENDS "test_pcap;test_nanowire" TIMEOUT 300)
endif()
