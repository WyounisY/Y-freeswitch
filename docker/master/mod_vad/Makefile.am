#BASE=/usr/src/freeswitch
#LOCAL_CFLAGS=-I/usr/src/libfvad/include
#LOCAL_LDFLAGS=-L/usr/local/lib/ -lfvad 
#include $(BASE)/build/modmake.rules
include $(top_srcdir)/build/modmake.rulesam
MODNAME=mod_vad

mod_LTLIBRARIES = mod_vad.la
mod_vad_la_SOURCES  = mod_vad.c
mod_vad_la_CFLAGS   = $(AM_CFLAGS)
mod_vad_la_CPPFLAGS = -I/usr/src/libfvad/include
mod_vad_la_LIBADD   = $(switch_builddir)/libfreeswitch.la  -lfvad
mod_vad_la_LDFLAGS  = -avoid-version -module -no-undefined -shared

#1.10
BASE=/usr/src/freeswitch/
LOCAL_CFLAGS=-I/libfvad/include
LOCAL_LDFLAGS=-L/usr/local/lib/ -lfvad 
include $(BASE)/build/modmake.rules