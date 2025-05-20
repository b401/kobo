##
# Project Kobo
#
# @file
# @version 0.1
build:
	gcc -fPIC -shared kobo_lib.c -o kobo_lib.so
	xxd -i kobo_lib.so kobo_lib_so.h
	gcc kobo.c -o kobo
	rm kobo_lib.so kobo_lib_so.h
# end
