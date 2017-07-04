#!/bin/bash
#********************************************************************************
#                  COPYRIGHT © 2002-2016 EMC CORPORATION                     	*
#                        ---ALL RIGHTS RESERVED---                             	*
#********************************************************************************
#

OS_NAME="Linux"

for sample in async sync sync2 sync3 acestatus acestatusEx; do
    cd $sample
    ./build.sh
    cd ..
done

