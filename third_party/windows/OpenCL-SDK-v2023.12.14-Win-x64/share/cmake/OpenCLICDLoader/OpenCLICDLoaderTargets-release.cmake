#----------------------------------------------------------------
# Generated CMake target import file for configuration "Release".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "OpenCL::OpenCL" for configuration "Release"
set_property(TARGET OpenCL::OpenCL APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(OpenCL::OpenCL PROPERTIES
  IMPORTED_IMPLIB_RELEASE "${_IMPORT_PREFIX}/lib/OpenCL.lib"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/bin/OpenCL.dll"
  )

list(APPEND _cmake_import_check_targets OpenCL::OpenCL )
list(APPEND _cmake_import_check_files_for_OpenCL::OpenCL "${_IMPORT_PREFIX}/lib/OpenCL.lib" "${_IMPORT_PREFIX}/bin/OpenCL.dll" )

# Import target "OpenCL::cllayerinfo" for configuration "Release"
set_property(TARGET OpenCL::cllayerinfo APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(OpenCL::cllayerinfo PROPERTIES
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/bin/cllayerinfo.exe"
  )

list(APPEND _cmake_import_check_targets OpenCL::cllayerinfo )
list(APPEND _cmake_import_check_files_for_OpenCL::cllayerinfo "${_IMPORT_PREFIX}/bin/cllayerinfo.exe" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
