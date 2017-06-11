#
# - Try to find GModule2
# Find GModule headers, libraries and the answer to all questions.
#
#  GMODULE2_FOUND               True if GMODULE2 got found
#  GMODULE2_INCLUDE_DIRS        Location of GMODULE2 headers
#  GMODULE2_LIBRARIES           List of libraries to use GMODULE2
#
#  Copyright (c) 2008 Bjoern Ricks <bjoern.ricks@googlemail.com>
#
#  Redistribution and use is allowed according to the terms of the New
#  BSD license.
#  For details see the accompanying COPYING-CMAKE-SCRIPTS file.
#

include( FindWSWinLibs )

if( ENABLE_GTK3 )
	FindWSWinLibs( "gtk3" "GMODULE2_HINTS" )
else()
	FindWSWinLibs( "gtk2" "GMODULE2_HINTS" )
endif()

find_package( PkgConfig )

if( GLIB2_MIN_VERSION )
	pkg_search_module( GLIB2 glib-2.0>=${GLIB2_MIN_VERSION} )
else()
	pkg_search_module( GLIB2 glib-2.0 )
endif()

find_path( GMODULE2_INCLUDE_DIRS
	NAMES
		gmodule.h
	PATH_SUFFIXES
		glib-2.0
	HINTS
		"${GMODULE2_HINTS}/include"
)
find_library( GMODULE2_LIBRARIES NAMES gmodule-2.0 gmodule HINTS "${GMODULE2_HINTS}/lib" )

include( FindPackageHandleStandardArgs )
find_package_handle_standard_args( GMODULE2 DEFAULT_MSG GMODULE2_LIBRARIES GMODULE2_INCLUDE_DIRS )

mark_as_advanced( GMODULE2_LIBRARIES GMODULE2_INCLUDE_DIRS )
