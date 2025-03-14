include(FetchContent)
include(ExternalProject)

cmake_minimum_required(VERSION 3.5.0)
set(CMAKE_CXX_STANDARD 20)

project(SHclient VERSION 0.1.3 LANGUAGES C CXX)
add_executable(SHclient_test src/main.cpp)
set(TARGETS SHclient_test)
set(BUILD_TESTING OFF)

FetchContent_Declare(json URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz)
FetchContent_Declare(pugixml GIT_REPOSITORY https://github.com/zeux/pugixml)
FetchContent_MakeAvailable(json pugixml)

find_package(OpenSSL REQUIRED)

set(LIBRARYS nlohmann_json::nlohmann_json OpenSSL::SSL pugixml::static paho-mqttpp3 paho-mqtt3as)

include_directories(${CMAKE_SOURCE_DIR}/include
                    ${CMAKE_SOURCE_DIR}/include/rapidxml
                    paho.mqtt.cpp/src
                    paho.mqtt.cpp/externals/paho-mqtt-c/src)

link_directories(${CMAKE_SOURCE_DIR}/library
paho.mqtt.cpp/build/externals/paho-mqtt-c/src
paho.mqtt.cpp/build/src)

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
