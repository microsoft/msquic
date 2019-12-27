function(CLOG_ADD_SOURCEFILE)
	set(library ${ARGV0})
	list(REMOVE_AT ARGV 0)
	
	# message(STATUS "CLOG : ADDING SOURCE FILES TO LIBRARY ${library}")
	
    foreach(arg IN LISTS ARGV)
        #message(STATUS "${arg} CLOG FILE: ${CMAKE_CURRENT_SOURCE_DIR}/${arg}")         
        #message(STATUS "    ${CMAKE_SOURCE_DIR}/submodules/clog/bld/clog -c ${CMAKE_SOURCE_DIR}/submodules/clog/clog.config -s /mnt/c/temp/clog.sidecar -i ${CMAKE_CURRENT_SOURCE_DIR}/${arg} -o ${CMAKE_CLOG_OUTPUT_DIRECTORY}/${arg}.clog")

        string(MAKE_C_IDENTIFIER ${CMAKE_CURRENT_SOURCE_DIR}, PATH_HASH)
        set(ARG_DEPENDENCY generate_clog_${arg}_${PATH_HASH})
        set(ARG_CLOG_FILE ${CMAKE_CLOG_OUTPUT_DIRECTORY}/${arg}.clog)
		set(ARG_CLOG_C_FILE ${CMAKE_CLOG_OUTPUT_DIRECTORY}/${arg}.clog.lttng.h.c)

        # message(STATUS "   ${ARG_DEPENDENCY}")

        add_custom_command(
            OUTPUT ${ARG_CLOG_FILE} ${ARG_CLOG_C_FILE}
            COMMENT "ULOG: ${CMAKE_SOURCE_DIR}/submodules/clog/bld/clog -t ${CMAKE_SOURCE_DIR}/submodules/clog/clog.config -s /mnt/c/temp/clog.sidecar -i ${CMAKE_CURRENT_SOURCE_DIR}/${arg} -o ${ARG_CLOG_FILE}"
            COMMAND ${CMAKE_SOURCE_DIR}/submodules/clog/bld/clog -c ${CMAKE_SOURCE_DIR}/manifest/clog.config -s /mnt/c/temp/clog.sidecar -i ${CMAKE_CURRENT_SOURCE_DIR}/${arg} -o ${ARG_CLOG_FILE}
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
		
		# message(STATUS "***ADDING : ${arg}")
		set(clogfiles ${clogfiles} ${ARG_CLOG_C_FILE})
		
    endforeach()
	
	set(${library} ${${library}} ${clogfiles} PARENT_SCOPE)
	# message(STATUS "*_*_*_*_*_*_* Done with adding source files")
endfunction()
