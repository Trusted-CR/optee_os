echo -e "Executing binary $1"
sleep 5 && ./checkpoint.sh $1 &
./$1

