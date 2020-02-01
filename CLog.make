function(CLOG_ADD_SOURCEFILE)
	set(library ${ARGV0})
	list(REMOVE_AT ARGV 0)
    message(STATUS "****************<<<<<<<   CLOG(${library}))    >>>>>>>>>>>>>>>*******************")
	
	set(CMAKE_CLOG_BINS_DIRECTORY ${CMAKE_SOURCE_DIR}/artifacts/tools/bin/clog)
	set(CMAKE_CLOG_SIDECAR_DIRECTORY ${CMAKE_SOURCE_DIR}/manifest)

    foreach(arg IN LISTS ARGV)
        string(MAKE_C_IDENTIFIER ${CMAKE_CURRENT_SOURCE_DIR}, PATH_HASH)
        set(ARG_DEPENDENCY generate_clog_${arg}_${PATH_HASH})
        set(ARG_CLOG_FILE ${CMAKE_CLOG_OUTPUT_DIRECTORY}/${arg}.clog)
		set(ARG_CLOG_C_FILE ${CMAKE_CLOG_OUTPUT_DIRECTORY}/${library}_${arg}.clog.c)
		
		add_custom_command(
			WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/submodules/clog
			COMMENT "Building CLOG and its support tooling"
			OUTPUT ${CMAKE_CLOG_BINS_DIRECTORY}/clog.dll
			COMMAND dotnet build ./clog.sln/clog.sln -o ${CMAKE_CLOG_BINS_DIRECTORY}
		)
			
        add_custom_command(
            OUTPUT ${ARG_CLOG_FILE} ${ARG_CLOG_C_FILE}
			DEPENDS ${CMAKE_CLOG_BINS_DIRECTORY}/clog.dll
            #DEPENDS ${CMAKE_CLOG_CONFIG_FILE}
            DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${arg}
            COMMENT "ULOG: ${CMAKE_CLOG_BINS_DIRECTORY}/clog --scopePrefix ${library} -c ${CMAKE_CLOG_CONFIG_FILE} -s ${CMAKE_CLOG_SIDECAR_DIRECTORY}/clog.sidecar -i ${CMAKE_CURRENT_SOURCE_DIR}/${arg} -o ${ARG_CLOG_FILE}"
            COMMAND ${CMAKE_CLOG_BINS_DIRECTORY}/clog --scopePrefix ${library} -c ${CMAKE_CLOG_CONFIG_FILE} -s ${CMAKE_CLOG_SIDECAR_DIRECTORY}/clog.sidecar -i ${CMAKE_CURRENT_SOURCE_DIR}/${arg} -o ${ARG_CLOG_FILE}
        )

        add_custom_target(${ARG_DEPENDENCY}
            COMMENT "CUSTOM TARGET for ${arg} : ${ARG_DEPENDENCY}"
        )

        set_property(TARGET CLOG_GENERATED_FILES
            APPEND PROPERTY OBJECT_DEPENDS ${ARG_CLOG_FILE}
            APPEND PROPERTY OBJECT_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${arg}
        )
      			
        list(APPEND clogfiles ${ARG_CLOG_C_FILE})
    endforeach()

    add_library(${library} STATIC ${clogfiles})

   
    message(STATUS "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^")
endfunction()