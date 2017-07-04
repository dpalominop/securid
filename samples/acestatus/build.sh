#!/bin/bash 
#
# Build script for the acestatus_a, acestatus_so. 
#
#********************************************************************************
#*                  COPYRIGHT © 2002-2016 EMC CORPORATION                      	*
#*						   ---ALL RIGHTS RESERVED---							*
#********************************************************************************
#

############################################################
# Set default values and commands for the shell script.
############################################################
clear

OS_NAME="Linux"
is64="false"
if [ $OS_NAME = "HP-UX" ] ; then
		if [ `uname -r | cut -f 2 -d '.'` = "11" ] ; then
			OS_NAME=HP11_UX
		else
			OS_NAME=HP_UX
		fi	
		if [ `getconf KERNEL_BITS` = "64" ] ; then
			is64="true"
		fi
fi
if [ $OS_NAME = "AIX" ] ; then
		OS_NAME=Aix
		if [ `bootinfo -K` = "64" ] ; then
		    export OBJECT_MODE=64
			is64="true"
		fi
fi
if [ $OS_NAME = "Linux" ] ; then
		OS_NAME=LinuxAS
		if [ `getconf LONG_BIT` = "64" ] ; then
			is64="true"
		fi
fi
if [ $OS_NAME = "SunOS" ] ; then
	ARCH=`uname -p`
	if [ "$ARCH" = "i386" ] ; then
		OS_NAME=SunOS_x86
		if [ `/usr/bin/isainfo -kv | cut -f 1 -d '-'` = "64" ] ; then
			is64="true"
		fi
        else
		OS_NAME=SunOS_SPARC
		if [ `/usr/bin/isainfo -kv | cut -f 1 -d '-'` = "64" ] ; then
			is64="true"
		fi
	fi
fi

case $OS_NAME in
Windows_NT)
        nmake -f Makefile.Windows_NT
        ;;
*)
	if [ "$is64" = "true" ]; then
        	make -f Makefile.${OS_NAME}_64
        fi
		if [ $OS_NAME = "Aix" ] ; then
                export OBJECT_MODE=32
		fi

       	make -f Makefile.${OS_NAME}_32
	;;
esac
