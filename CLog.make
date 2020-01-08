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
		set(ARG_CLOG_C_FILE ${CMAKE_CLOG_OUTPUT_DIRECTORY}/${arg}.clog.c)
		
		add_custom_command(
			WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/submodules/clog
			COMMENT "Building CLOG and its support tooling"
			OUTPUT ${CMAKE_CLOG_BINS_DIRECTORY}/clog.dll
			COMMAND dotnet build ./clog.sln/clog.sln -o ${CMAKE_CLOG_BINS_DIRECTORY}
		)
			
        add_custom_command(
            OUTPUT ${ARG_CLOG_FILE} ${ARG_CLOG_C_FILE}
			DEPENDS ${CMAKE_CLOG_BINS_DIRECTORY}/clog.dll
            COMMENT "ULOG: ${CMAKE_CLOG_BINS_DIRECTORY}/clog -c ${CMAKE_SOURCE_DIR}/manifest/clog.config -s ${CMAKE_CLOG_SIDECAR_DIRECTORY}/clog.sidecar -i ${CMAKE_CURRENT_SOURCE_DIR}/${arg} -o ${ARG_CLOG_FILE}"
            COMMAND ${CMAKE_CLOG_BINS_DIRECTORY}/clog -c ${CMAKE_SOURCE_DIR}/manifest/clog.config -s ${CMAKE_CLOG_SIDECAR_DIRECTORY}/clog.sidecar -i ${CMAKE_CURRENT_SOURCE_DIR}/${arg} -o ${ARG_CLOG_FILE}
        )
              
        add_custom_target(${ARG_DEPENDENCY}
            COMMENT "CUSTOM TARGET for ${arg} : ${ARG_DEPENDENCY}"
        )

        set_property(SOURCE ${arg}
            APPEND PROPERTY OBJECT_DEPENDS ${ARG_CLOG_FILE}
        )
		
		set_property(SOURCE ${arg}
            APPEND PROPERTY OBJECT_DEPENDS ${ARG_CLOG_C_FILE}
        )
			
        list(APPEND clogfiles ${ARG_CLOG_C_FILE})
    endforeach()
	    

    foreach(arg IN LISTS ARGV)
        message(STATUS "++SRC_FILE ${arg}")
    endforeach()
    foreach(arg IN LISTS clogfiles)
        message(STATUS "+CLOG_FILE ${arg}")
    endforeach()
    list(APPEND foo ${clogfiles} ${${library}})
	set(${${library}} ${foo} PARENT_SCOPE)
    foreach(arg IN LISTS foo)
        message(STATUS "+MERGE ${arg}")
    endforeach()
    message(STATUS "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^")
   
endfunction()
