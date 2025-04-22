#cifuzz:build-template:begin
#add_fuzz_test({{ .FuzzTestName }} {{ .FileName }})
#target_link_libraries({{ .FuzzTestName }} PRIVATE "$<LINK_LIBRARY:WHOLE_ARCHIVE,RapidJSON>")
#cifuzz:build-template:end

add_fuzz_test(fuzz_test fuzz_test.cpp)
target_link_libraries(fuzz_test PRIVATE "$<LINK_LIBRARY:WHOLE_ARCHIVE,RapidJSON>")
