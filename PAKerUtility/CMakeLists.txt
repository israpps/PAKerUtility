cmake_minimum_required(VERSION 3.10)

project(PAKerUtility)

include_directories("include")
add_executable(PAKerUtility
    main.c
    PAK.c
    PAKCrypt.c
)
