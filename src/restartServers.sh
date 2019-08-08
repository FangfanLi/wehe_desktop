#!/bin/bash

screen -X -S analyzer quit
screen -X -S replay quit

sleep 5

cd /home/ubuntu/DD/src/

screen -S analyzer -d -m sudo python replay_analyzerServer.py --ConfigFile=configs.cfg --original_ports=True

echo Started replay analyzer

sleep 5

screen -S replay -d -m sudo python replay_server.py --ConfigFile=configs.cfg --original_ports=True

echo Started replay server
