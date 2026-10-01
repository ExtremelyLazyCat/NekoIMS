# Builds opencore-amr / vo-amrwbenc as plain CMake static libraries, for
# platforms where their autotools build can't run (Windows/MSVC).
#
# Source lists are read from the upstream Makefile.am so they stay in sync
# with the pinned release. Only *_SOURCES assignments are used; automake
# conditionals are evaluated with the codec halves enabled and everything else
# (ARM assembly, COMPILE_AS_C, examples) off, matching the default configure.

set(_AMR_TRUE_CONDS AMRNB_DECODER AMRNB_ENCODER)

function(amr_makefile_am_sources out dir)
  file(STRINGS "${dir}/Makefile.am" lines)
  set(vars "top_srcdir=${_amr_top}")
  set(srcs "")
  set(active 1)         # are we inside only true conditionals?
  set(active_stack "")  # enclosing "active" per open "if"
  set(cond_stack "")    # condition value per open "if"
  set(in_sources 0)

  foreach(line IN LISTS lines)
    if(line MATCHES "^[ \t]*#")
      continue()
    endif()

    if(line MATCHES "^[ \t]*if[ \t]+(!?)([A-Za-z0-9_]+)")
      set(cond 0)
      if(CMAKE_MATCH_2 IN_LIST _AMR_TRUE_CONDS)
        set(cond 1)
      endif()
      if(CMAKE_MATCH_1)
        math(EXPR cond "1 - ${cond}")
      endif()
      list(APPEND active_stack ${active})
      list(APPEND cond_stack ${cond})
      if(NOT cond)
        set(active 0)
      endif()
      set(in_sources 0)
      continue()
    elseif(line MATCHES "^[ \t]*else[ \t]*$")
      list(GET active_stack -1 parent)
      list(GET cond_stack -1 cond)
      if(parent AND NOT cond)
        set(active 1)
      else()
        set(active 0)
      endif()
      set(in_sources 0)
      continue()
    elseif(line MATCHES "^[ \t]*endif[ \t]*$")
      list(POP_BACK active_stack active)
      list(POP_BACK cond_stack)
      set(in_sources 0)
      continue()
    endif()

    if(NOT active)
      continue()
    endif()

    if(line MATCHES "^[ \t]*([A-Za-z0-9_]+)[ \t]*(\\+?=)[ \t]*(.*)$")
      set(name "${CMAKE_MATCH_1}")
      set(op "${CMAKE_MATCH_2}")
      set(value "${CMAKE_MATCH_3}")
      if(name MATCHES "_SOURCES$" AND NOT name MATCHES "^(nodist_|EXTRA_)")
        set(in_sources 1)
        set(line "${value}")
      else()
        if(op STREQUAL "=")
          list(APPEND vars "${name}=${value}")
        endif()
        set(in_sources 0)
        continue()
      endif()
    elseif(NOT in_sources)
      continue()
    endif()

    set(continued 0)
    if(line MATCHES "\\\\[ \t]*$")
      set(continued 1)
    endif()
    string(REPLACE "\\" " " line "${line}")
    separate_arguments(toks UNIX_COMMAND "${line}")
    foreach(tok IN LISTS toks)
      if(tok MATCHES "\\.(c|cpp)$")
        list(APPEND srcs "${tok}")
      endif()
    endforeach()
    if(NOT continued)
      set(in_sources 0)
    endif()
  endforeach()

  # Expand $(VAR) references; values may refer to earlier variables.
  set(result "")
  foreach(src IN LISTS srcs)
    foreach(i RANGE 4)
      foreach(kv IN LISTS vars)
        string(FIND "${kv}" "=" eq)
        string(SUBSTRING "${kv}" 0 ${eq} k)
        math(EXPR eq "${eq} + 1")
        string(SUBSTRING "${kv}" ${eq} -1 v)
        string(REPLACE "$(${k})" "${v}" src "${src}")
      endforeach()
    endforeach()
    if(NOT IS_ABSOLUTE "${src}")
      set(src "${dir}/${src}")
    endif()
    if(src MATCHES "\\$\\(" OR NOT EXISTS "${src}")
      message(FATAL_ERROR "AMR: cannot resolve source '${src}' from ${dir}/Makefile.am")
    endif()
    list(APPEND result "${src}")
  endforeach()

  if(NOT result)
    message(FATAL_ERROR "AMR: no sources found in ${dir}/Makefile.am")
  endif()
  set(${out} ${result} PARENT_SCOPE)
endfunction()

# opencore_src: extracted opencore-amr tree, vo_src: extracted vo-amrwbenc
# tree, inc_dir: where public headers are staged in the
# <inc_dir>/{opencore-amrnb,opencore-amrwb,vo-amrwbenc} layout FindAMR expects.
function(amr_add_libraries opencore_src vo_src inc_dir)
  set(gsm "${opencore_src}/opencore/codecs_v2/audio/gsm_amr")

  set(_amr_top "${opencore_src}")
  amr_makefile_am_sources(nb_srcs "${opencore_src}/amrnb")
  amr_makefile_am_sources(wb_srcs "${opencore_src}/amrwb")
  set(_amr_top "${vo_src}")
  amr_makefile_am_sources(vo_srcs "${vo_src}")

  add_library(opencore-amrnb STATIC ${nb_srcs})
  target_include_directories(opencore-amrnb PRIVATE
    ${opencore_src}/oscl
    ${gsm}/amr_nb/dec/src
    ${gsm}/amr_nb/common/include
    ${gsm}/amr_nb/dec/include
    ${gsm}/common/dec/include
    ${gsm}/amr_nb/enc/src
  )

  add_library(opencore-amrwb STATIC ${wb_srcs})
  target_include_directories(opencore-amrwb PRIVATE
    ${opencore_src}/oscl
    ${gsm}/amr_wb/dec/src
    ${gsm}/amr_wb/dec/include
    ${gsm}/common/dec/include
  )

  add_library(vo-amrwbenc STATIC ${vo_srcs})
  target_include_directories(vo-amrwbenc PRIVATE
    ${vo_src}/amrwbenc/inc
    ${vo_src}/common/include
  )

  foreach(t opencore-amrnb opencore-amrwb vo-amrwbenc)
    if(MSVC)
      # Fixed-point DSP code, full of int narrowing; upstream builds with -w.
      target_compile_options(${t} PRIVATE /w)
      target_compile_definitions(${t} PRIVATE _CRT_SECURE_NO_WARNINGS)
    else()
      target_compile_options(${t} PRIVATE -w)
    endif()
  endforeach()

  file(COPY ${opencore_src}/amrnb/interf_dec.h ${opencore_src}/amrnb/interf_enc.h
       DESTINATION ${inc_dir}/opencore-amrnb)
  file(COPY ${opencore_src}/amrwb/dec_if.h ${opencore_src}/amrwb/if_rom.h
       DESTINATION ${inc_dir}/opencore-amrwb)
  file(COPY ${vo_src}/enc_if.h DESTINATION ${inc_dir}/vo-amrwbenc)
endfunction()
