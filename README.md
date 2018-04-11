# Wehe

## Running one replay using wehe Server:

The replay traces that Wehe uses can be found here:
https://github.com/FangfanLi/wehe_replayTraces.

Assume now you have donwload the traces, and they are stored in the/dir/to/replayTraces.

On your laptop:

* Assume the server used is wehe (you can use your own server as well, just edit ```class Instance``` in python_lib.py, which will be explained in the following section). 
* You can then run a replay for Youtube by

```
python replay_client.py --pcap_folder=the/dir/to/replayTraces/Youtube --serverInstance=wehe
```

## Running a differentiation test using wehe Server:
Now you want to test whether there is DPI based differentiation on Youtube.

```
python differentiationTest.py --pcap_folder=the/dir/to/replayTraces/Youtube --serverInstance=wehe
```

The output is either differentiation or not, and the average throughputs for the original trace and randomized trace.

## Deploy your own server:

* Move the replayTraces on to the server, assuming the directory is server/dir/to/replayTraces
* Edit the path in folders.txt to where the replayTraces are
* Now you can start both the server and analyzer

```
sudo python replay_server.py --ConfigFile=configs_local.cfg --original_ports=True 
```

```
sudo python replay_analyzerServer.py --ConfigFile=configs_local.cfg --original_ports=True 
```

One last thing is to add your server's address to Instance() class in python_lib.py, and assuming you named it 'myserver' there.

You should now be able to run the test with your own server 


```
python differentiationTest.py --pcap_folder=the/dir/to/replayTraces/Youtube --serverInstance=myserver
```

## Record traffic on your own

Use Wireshark to capture network traffic on your laptop.

Manually single out the traffic that you are interested in (e.g. the connection that carries most of the payload from a video streaming App).

Save the singled-out pcap file in a directory, let's call it the/dir/to/recordedTrace, make a file with the name 'client_ip.txt' with a single line of the client IP address in this recorded trace.

You can now parse the trace into the format that can be replayed by:
```
sudo python replay_parser.py --pcap_folder=the/dir/to/recordedTrace
```

Then copy the recordedTrace directory into another directory called recordedTraceRandom, rename the pcap file with string 'Random' appended at the end as well.

Then create the trace with content randomized/inverted for the controlled experiment, and there are two ways to do that.

* To randomize the payload in the original traffic (replace the original content with random strings)

```
sudo python replay_parser.py --pcap_folder=the/dir/to/recordedTraceRandom --randomPayload=True --pureRandom=True
```

* Do bit inversion in the original traffic (invert every bit in the content)

```
sudo python replay_parser.py --pcap_folder=the/dir/to/recordedTraceRandom --randomPayload=True --bitInvert=True
```

The last step is just to make sure changing the folders.txt file on the server to include your newly created replay trace.