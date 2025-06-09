find_program(XXD xxd)
if (NOT XXD)
    message(FATAL_ERROR "xxd not found")
endif()

if (TARGET_C_COMPILER)
    set(CLANG "${TARGET_C_COMPILER}")
else()
    set(CLANG "${LLVM_TOOLS_BINARY_DIR}/clang")
endif()

message(STATUS "Using compiler: ${CLANG}")
message(STATUS "Using xxd: ${XXD}")

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/decode.h
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/generate_ir_header.sh
            ${CLANG} ${XXD}
            ${CMAKE_CURRENT_SOURCE_DIR}/decode.c
            ${CMAKE_CURRENT_BINARY_DIR} decode.h
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/decode.c
)

add_custom_target(generateDecodeIRHeader ALL
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/decode.h
)
target_sources(LLVMObfuscator PRIVATE StringObfuscation.cpp)
find_package(LLVM REQUIRED CONFIG)
llvm_map_components_to_libnames(llvm_libs core irreader support)
#target_link_libraries(LLVMObfuscator PRIVATE ${llvm_libs})
add_dependencies(LLVMObfuscator generateDecodeIRHeader)
