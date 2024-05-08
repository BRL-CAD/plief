#
# This file is modeled after appleseed.
# Visit https://appleseedhq.net/ for additional information and resources.
#
# This software is released under the MIT license.
#
# Copyright (c) 2014-2018 Esteban Tovagliari, The appleseedhq Organization
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#

###
# - Find LIEF
# Find the native LIEF includes and library
#
#  LIEF_INCLUDE_DIR   - where to find include headers
#  LIEF_LIBRARIES     - List of libraries when using assetimport.
#
###
# - helpful cmake flags when building
#
#  LIEF_ROOT          - path to assetimport root if it is built outside of /usr
#
#=============================================================================
set(_LIEF_SEARCHES)

# Search LIEF_ROOT first if it is set.
if(LIEF_ROOT)
  set(_LIEF_SEARCH_ROOT PATHS ${LIEF_ROOT} NO_DEFAULT_PATH)
  list(APPEND _LIEF_SEARCHES _LIEF_SEARCH_ROOT)
endif()

set(LIEF_NAMES LIEF)

# Try each search configuration.
foreach(search ${_LIEF_SEARCHES})
  find_path(LIEF_INCLUDE_DIR
    NAMES LIEF/version.h
    ${${search}} PATH_SUFFIXES include)
  find_library(LIEF_LIBRARY
    NAMES ${LIEF_NAMES}
    ${${search}} PATH_SUFFIXES lib lib64)
endforeach()

if (NOT LIEF_LIBRARY OR NOT LIEF_INCLUDE_DIR)
  # Try a more generic search
  find_path(LIEF_INCLUDE_DIR
    NAMES LIEF/version.h
    PATH_SUFFIXES include)
  find_library(LIEF_LIBRARY
    NAMES ${LIEF_NAMES}
    PATH_SUFFIXES lib lib64)
endif (NOT LIEF_LIBRARY OR NOT LIEF_INCLUDE_DIR)

# Handle the QUIETLY and REQUIRED arguments and set LIEF_FOUND.
include (FindPackageHandleStandardArgs)
find_package_handle_standard_args (LIEF REQUIRED_VARS
  LIEF_LIBRARY
  LIEF_INCLUDE_DIR
  )

# Set the output variables.
if (LIEF_FOUND)
  set (LIEF_INCLUDE_DIRS ${LIEF_INCLUDE_DIR})
  set (LIEF_LIBRARIES ${LIEF_LIBRARY})
  if(NOT TARGET LIEF::LIEF)
    add_library(LIEF::LIEF UNKNOWN IMPORTED)
    set_target_properties(LIEF::LIEF PROPERTIES
      IMPORTED_LOCATION "${LIEF_LIBRARIES}"
      INTERFACE_INCLUDE_DIRECTORIES "${LIEF_INCLUDE_DIRS}")
  endif()
else ()
  set (LIEF_INCLUDE_DIRS)
  set (LIEF_LIBRARIES)
endif ()

mark_as_advanced (
  LIEF_INCLUDE_DIR
  LIEF_LIBRARY
  )

# Local Variables:
# tab-width: 8
# mode: cmake
# indent-tabs-mode: t
# End:
# ex: shiftwidth=2 tabstop=8
