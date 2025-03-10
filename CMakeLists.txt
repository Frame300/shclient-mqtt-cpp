include(FetchContent)

cmake_minimum_required(VERSION 3.5.0)
set(CMAKE_CXX_STANDARD 20)

project(SHclient VERSION 0.1.3 LANGUAGES C CXX)
add_executable(SHclient_test src/main.cpp)
set(TARGETS SHclient_test)
set(BUILD_TESTING OFF)

FetchContent_Declare(json URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz)
FetchContent_MakeAvailable(json)

find_package(OpenSSL REQUIRED)
find_package(pugixml REQUIRED)
set(LIBRARYS nlohmann_json::nlohmann_json OpenSSL::SSL pugixml)

include_directories(${CMAKE_SOURCE_DIR}/include
                    ${CMAKE_SOURCE_DIR}/include/rapidxml)

link_directories(${CMAKE_SOURCE_DIR}/library)

foreach(TARGET ${TARGETS})
message(${TARGET})
    foreach(LIBRARY ${LIBRARYS})    
        target_link_libraries(${TARGET} PRIVATE ${LIBRARY})
    endforeach()
    
    add_custom_command(TARGET ${TARGET} PRE_BUILD
                    COMMAND ${CMAKE_COMMAND} -E copy_directory
                        ${CMAKE_SOURCE_DIR}/src/config/ $<TARGET_FILE_DIR:${TARGET}>)
endforeach()

#set_target_properties(SHclient_test PROPERTIES
#    CXX_STANDARD_REQUIRED ON
#    CXX_EXTENSIONS OFF
#)
