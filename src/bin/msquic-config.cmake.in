include(CMakeFindDependencyMacro)

include("${CMAKE_CURRENT_LIST_DIR}/msquic.cmake")

# Legacy names
if(NOT TARGET msquic)
    add_library(msquic ALIAS msquic::msquic)
endif()
if(NOT TARGET msquic_platform)
    add_library(msquic_platform ALIAS msquic::platform)
endif()
