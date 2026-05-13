# Specificaiton-Guided Lateral Movement Detectiong using eBPF
## CSCI4271-win26-Group2
Nir Kazatsker

Miriam Okutuo

Manveer Singh Pabla

Amogh Sharma

Setup instructions: 
```
# Clone the repository
git clone https://github.com/PINetDalhousie/CSCI4271-win26-Group2.git

# install dependencies:
pip install -r requirements.txt

# install BCC from the BCC Github.
```

## Instructions to run the project
There are two ways to run this project. 

1. Deploy the system on a simulated network (Mininet).

Step 1. Deploy the default mininet topology using `sudo mn`.

Step 2. Open two terminal windows into the hosts using `xterm h1 h2`. 

Step 3. In the terminal window for h2, start the hopper program using `python3 hopper.py`

Step 4. In the terminal window for h1, send packets to hopper using `python3 sendPackets.py`

Step 5. Once `sendPackets.py` finishes running, press `Control C` (or your Interrupt Key) to process graph results. 

The traffic simulation may take multiple hours to days depending on how much data you are processing, which is why we recommended for evaluating the algorithm to use the second method. 

2. Only evaluating the algorithm.

Step 1. Run `hopperPrototypeTest.py` directly using `python3 hopperPrototypeTest.py`

This will clean the data, run the detection algorithm and output results of the algorithm.

All data is located in the folder `auth/`. If you want to change which data you want evaluated, modify `cleanData.py` top for loop to indicate the range of dataset you want to run. 


---------

Dataset information:

The relevant dataset in its entirety can be downloaded [here](https://dalu.sharepoint.com/:u:/t/TAChannel-CSCI6709-SDN/IQDuJrmO8RbFRY7iJP-TGV4GATdkiYFvqx9Abet5lVYO7XY?e=p4Hoof)

The first portion is included here divided into 15 100MB files, the largest possible for GitHub.

---------
### Payload Details for eBPF:

Payload Contract (39 bytes, UTF-8 encoded, fixed-width):
- bytes 0–4   : time     (5 bytes, zero-padded integer e.g. "00001")
- bytes 5-15  : src_user (11 bytes, space-padded string)
- butes 16-26 : dst_user (11 bytes, space-padded string)
- bytes 27–32 : src_host (6 bytes, space-padded string  e.g. "C1250.")
- bytes 33–38 : dst_host (6 bytes, space-padded string  e.g. "C586..")

Transport:
- Protocol : UDP
- dst IP   : 10.0.0.2 (or the IP address of where Hopper sits)
- dst port : 9999

To run: sudo python3 sendPackets.py