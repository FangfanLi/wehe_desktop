# DifferentiationDetector

This software is covered by the CRAPL licence (see CRAPL-LICENSE.txt)

How to run a replay step by step:

Prepare the replay traffic, the replay is recorded in a pcap file, and we will use the parser script to process the pcap and create the pickle file that can be used by the client and server.

Assume the pcap is stored in the/dir/to/pcap.

On the client:

* Create the pickle with original payload

```bash
sudo python replay_parser.py --pcap_folder=the/dir/to/pcap
```

* To randomize the payload in the original traffic (replace the original content with random strings)

```bash
sudo python replay_parser.py --pcap_folder=the/dir/to/pcap --randomPayload=True --pureRandom=True
```

* Do bit inversion in the original traffic (invert every bit in the content)

```bash
sudo python replay_parser.py --pcap_folder=the/dir/to/pcap --randomPayload=True --bitInvert=True
```

* Copy the pickle directory (the/dir/to/pcap) to the server via scp


On the server:

* Change the content in folders.txt to where the replay pickle is (in this example, it can be ../DD/data/Youtube and ../DD/data/YoutubeRandom)
* You can now run the replay_server
```bash
sudo python replay_server.py --ConfigFile=configs_local.cfg
```

On the client:

* Assume the server used is replay-test-2 (can use your own server as well, just edit ```class Instance``` in python_lib.py). You can then run a replay of the recorded traffic

```bash
python replay_client.py --pcap_folder=the/dir/to/pcap --serverInstance=replay-test-2
```

## Containerization

This API has been containerized. To run it within a container first go to the cloned directory and build with 
```
sudo docker build . -t wehe
```

Then run with 
```
sudo docker run -v <where/to/save/the/output/on/host>:/data/RecordReplay --env SUDO_UID=$UID --net=host -itd wehe
```

Remove d from `-itd` to run outside of detached mode and see the output in STDOUT
