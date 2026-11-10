cmake_minimum_required(VERSION 3.16)

# Minimal AP/STA throughput probe used only for lab tests of the DELBA attack:
# one board runs "ap", the other "sta", and a third board attacks the link.
set(CMAKE_NINJA_FORCE_RESPONSE_FILE ON)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(rf_throughput)
