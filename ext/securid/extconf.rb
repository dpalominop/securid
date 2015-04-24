#!/usr/bin/env ruby

require 'mkmf'

dir_config('aceclnt')

have_header('acexport.h')
have_header('securid.h')
have_library('aceclnt')

create_makefile('securid/securid')
