cmake_minimum_required(VERSION 3.17)

set(HUNTER_Boost_COMPONENTS log system date_time thread  )
set(HUNTER_PACKAGES Boost)

include(FetchContent)
FetchContent_Declare(SetupHunter GIT_REPOSITORY https://github.com/cpp-pm/gate)
FetchContent_MakeAvailable(SetupHunter)

#target_link_libraries(... Boost::system Boost::filesystem)
project(ethash)


set(CMAKE_CXX_STANDARD 14)
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
find_package(Boost CONFIG REQUIRED log system date_time thread)

include_directories(${Boost_INCLUDE_DIRS})

add_executable(ethash main.cpp Ethash.cpp include/Ethash.h include/HashTypes.h include/PoW.h include/Endianess.h include/Keccak.h Keccak.cpp)
target_link_libraries(ethash PUBLIC Threads::Threads Boost::log Boost::system Boost::thread Boost::date_time)