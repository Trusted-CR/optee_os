export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/root/shared/lib
rm -rf /root/shared/checkpoint/*
pid="$(pidof -s $1)"
if test -z "$pid"
then
	echo -e "\nProcess $1 is not running"
	exit -1
else
	echo -e "\nCRIU"
	echo "Checkpointing $1 with PID $pid..."
fi

./criu dump -t `pidof $1` -D checkpoint --shell-job -v0
echo "PID $1 checkpointed!"

echo -e "\nCRIT Decoding"
echo -e -n "Decoding core-$pid.img..."
./crit.sh decode -i checkpoint/core-$pid.img --pretty > core-$pid.txt
echo -e "\tdone!"

echo -e -n "Decoding pagemap-$pid.img..."
./crit.sh decode -i checkpoint/pagemap-$pid.img --pretty > pagemap-$pid.txt
echo -e "\tdone!"

echo -e -n "Decoding mm-$pid.img..."
./crit.sh decode -i checkpoint/mm-$pid.img --pretty > mm-$pid.txt
echo -e "\t\tdone!"

echo -n "Copying pagedata..."
cp checkpoint/pages-1.img pages-1.img
echo -e "\t\tdone!"




echo -e "\n\nLinux - OP-TEE App Migrator"
./optee_app_migrator $pid $1



echo -e "\n\nCRIT Encoding"
echo -e -n "Encoding modfied core-$pid.img..."
./crit.sh encode -i modified_core.txt > checkpoint/core-$pid.img
echo -e "\tdone!"

echo -e -n "Encoding modfied pagemap-$pid.img..."
./crit.sh encode -i modified_pagemap.txt > checkpoint/pagemap-$pid.img
echo -e "\tdone!"

echo -e -n "Copying back pagedata..."
cp -rf modified_pages-1.img checkpoint/pages-1.img
echo -e "\t\tdone!"

echo -e "\nCRIU"
echo "Restoring the updated checkpoint"
./criu restore -D checkpoint --shell-job
