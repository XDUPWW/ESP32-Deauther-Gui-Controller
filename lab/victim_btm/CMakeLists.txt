cmake_minimum_required(VERSION 3.16)

# Lab-only 11KV victim station (802.11v BTM / 802.11k RRM enabled) with full
# disconnect-reason logging. Sibling of lab/rf_throughput, which stays untouched:
# that project provides the "ap" role, this one is only the station under test.
set(CMAKE_NINJA_FORCE_RESPONSE_FILE ON)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(victim_btm)
