#!/bin/bash

list="$(ps aux | grep ostools | grep -v grep)"
pids="$(echo -e "${list}" | awk '{print $2}')"

#if ((${#pids[@]} > 0)); then
    echo -e "\nRunning go servers:\n > ${list}\n"
    echo -e "\nBelow PIDs will be killed:\n > ${pids}\n"

    for pid in ${pids}
    do
        echo " -> killing $pid"
        kill -s 9 ${pid} && echo '    killed' || echo "     couldn't kill"
    done
#fi

echo -e "\nStaring a new server... "

./ostools >> /var/go/os-tools/logs/httpd.log 2>&1 &

echo -e "Done"

exit 0;