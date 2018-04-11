'''
#######################################################################################################
#######################################################################################################
Copyright 2018 Northeastern University

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Goal: read the parsed original traffic record (i.e., _client.pickle and _server.pickle)
from pcap_folder/original, then create new pickles with specified changes in pcap_folder

Usage:
    python replay_parserp.py --pcap_folder=[] --Side --PNum --Action --Specification

Mandatory arguments:

    pcap_folder: This is the folder containing pcap file and client_ip.txt

    PcapDir is where the replay pcap (pickle) files are
    Side: Client or Server modification
    PNum: the packet that need to be modified
    Action: what modification need to be made:
            Delete : Delete the specified packet from the trace
            Random : Randomize the whole packet and store the randomized packet into /random/randomClient.pickle and randomServer.pickle
          XOR    : Invert every bit in this packet and store the randomized packet into /random/randomClient.pickle and randomServer.pickle
          Prepend: Prepend random packets in front of the original packets
          ReplaceW : Replace multiple region with given strings specified by Specification
          ReplaceR : Replace multiple region with random bytes(random pickles) specified by Specification
          TTLP : For TTL probe, where the server is expecting original packets but receives random packets (original packets has limited TTL)

    Specification: specify how to make the modification on the trace
        When used in ReplaceW, it should be {(x,y):'something'...}, which would replace the payload from x to y byte to 'something'
        When used in ReplaceR, it should be {(x1,y1),(x2,y2)...}, which would replace the payload from x1 to y1 byte to
        the random payload from x1 to y1 byte(loaded from random pickle) and so on...



#######################################################################################################
#######################################################################################################
'''


import sys, os, pickle, copy, mimetools, StringIO, email, re, random, string
import python_lib
from python_lib import *


def MultiReplace(payload, regions, rpayload):
    # When randomPayload is '', that means we need to replace payload with the strings stores in regions
    # e.g. regions[(1,2):'haha']
    if rpayload == '':
        for region in regions:
            L = region[0]
            R = region[1]
            payload = Replace(payload, L, R, regions[region])
    else:
        for region in regions:
            L = region[0]
            R = region[1]
            payload = Replace(payload, L, R, rpayload[L:R])

    return payload

def Replace(payload, L, R, replaceS):
    # replace the bytes from L to R to replaceS
    payload = payload.decode('hex')
    plen = len(payload)
    if R > plen or L < 0 :
        print '\n\t\t ***Attention***Payload length is ',plen,'BUT L bond is ', L, 'R bond is',R,\
            'Returning original payload'
    else:
        LeftPad = payload[: L]
        RightPad = payload[R :]
        payload = LeftPad + replaceS + RightPad
    payload = payload.encode('hex')
    return payload

def to_list(chain, offset):
    return [chain[i:i+offset] for i in range(0, len(chain), offset)]

# Bit hex string operations
def bin2str(chain):
    return ''.join((chr(int(chain[i:i+8], 2)) for i in range(0, len(chain), 8)))

def bin2hex(chain):
    return ''.join((hex(int(chain[i:i+8], 2))[2:] for i in range(0, len(chain), 8)))

def str2bin(chain):
    return ''.join((bin(ord(c))[2:].zfill(8) for c in chain))

def str2hex(chain):
    return ''.join((hex(ord(c))[2:] for c in chain))

def hex2bin(chain):
    return ''.join((bin(int(chain[i:i+2], 16))[2:].zfill(8) for i in range(0, len(chain), 2)))

def hex2str(chain):
    return ''.join((chr(int(chain[i:i+2], 16)) for i in range(0, len(chain), 2)))

def XorPayload(payload):
    payload = payload.decode('hex')
    bpayload = str2bin(payload)
    newb = ''
    for char in bpayload:
        if char == '0':
            newb += '1'
        else:
            newb += '0'
    newpayload = bin2str(newb).encode('hex')
    return newpayload

# Randomize the whole payload in this packet
def Randomize(payload):
    # randomize the whole payload except the bytes from L to R
    payload = payload.decode('hex')
    plen = len(payload)
    payload = ''.join(chr(random.getrandbits(8)) for x in range(plen))
    payload = payload.encode('hex')

    return payload


def RandomLoad(pcapDir, side, PacketNum, Protocol, csp):
    # Client Side
    if side == 'Client':
        clientQ, udpClientPorts, tcpCSPs, replayName = \
            pickle.load(open(pcapDir +'/random/randomClient.pickle','r'))

        rpayload = clientQ[PacketNum-1].payload

    # Server Side
    else:
        serverQ, tmpLUT, tmpgetLUT, udpServers, tcpServerPorts, replayName = \
            pickle.load(open(pcapDir+'/random/randomServer.pickle','r'))
        if Protocol == 'udp':
            rpayload = serverQ[Protocol][csp][PacketNum-1].payload
        else:
            rpayload = serverQ[Protocol][csp][PacketNum-1].response_list[0].payload

    return rpayload

def RandomDump(pcapDir, clientQ, udpClientPorts, tcpCSPs, replay_name, serverQ, LUT, getLUT, udpServers, tcpServerPorts):
    if not os.path.isdir(pcapDir+'/random'):
        os.makedirs(pcapDir+'/random')

    pickle.dump((clientQ, udpClientPorts, list(tcpCSPs), replay_name),
                open((pcapDir+'/random/randomClient.pickle'), "w" ), 2)
    pickle.dump((serverQ, LUT, getLUT, udpServers, tcpServerPorts, replay_name),
                open((pcapDir+'/random/randomServer.pickle'), "w" ), 2)



# Client Modification:
# One thing to keep in mind is that the LUT is based on the payload in Client packet
# Thus the server LUT needs to be modified along with Client packet
def CModify(PcapDir, clientQ, LUT, getLUT, Prot, PNum, Action, Specification):
    # hash Sample size is fixed as 400
    toHash  = clientQ[PNum - 1].payload.decode('hex')[:400]
    theHash = hash(toHash)

    # Load the original value from LUT
    (replay_name, csp) = LUT[Prot][theHash]
    # Remove this entry in the hash table
    LUT[Prot].pop(theHash, None)

    if 'Random' == Action:
        clientQ[PNum-1].payload = Randomize(clientQ[PNum-1].payload)
    elif 'XOR' == Action:
        clientQ[PNum-1].payload = XorPayload(clientQ[PNum-1].payload)

    elif 'Delete' == Action:
        # print '\n\t Client Q Before deleting ::',clientQ
        clientQ.pop(PNum-1)
        # print '\n\t Client Q after deleting ::',clientQ

    elif 'Prepend' == Action:
        preNum = Specification[0]
        preLen = Specification[1]
        random.seed(Action)
        rstring = ''.join(random.choice(string.ascii_letters + string.digits) for x in range(preLen))
        for i in xrange(preNum):
            preQ = RequestSet(rstring.encode('hex'), clientQ[0].c_s_pair, None, clientQ[0].timestamp)
            clientQ.insert(0, preQ)
        # print '\n\t Client Q after prepending ::',TMPclientQ

    elif 'ReplaceW' == Action:
        regions = Specification
        clientQ[PNum-1].payload = MultiReplace(clientQ[PNum-1].payload, regions, '')
        # print '\n\t After ReplaceW ::',TMPclientQ[MPacketNum-1].payload.decode('hex')

    elif 'ReplaceR' == Action:
        regions = Specification
        rpayload = RandomLoad(PcapDir, 'Client', PNum, Prot, csp)
        rpayload = rpayload.decode('hex')
        clientQ[PNum-1].payload = MultiReplace(clientQ[PNum-1].payload, regions, rpayload)
        print '\r\n RRR', clientQ[PNum-1].payload.decode('hex')

    elif 'TTLP' == Action:
        # Fixed random seed, since the server need to know what to expect
        random.seed('TTLP')
        for i in xrange(PNum):
            Qlen = len(clientQ[i].payload.decode('hex'))
            rstring =  ''.join(random.choice(string.ascii_letters + string.digits) for x in range(Qlen))
            clientQ[i].payload = rstring.encode('hex')

    else:
        print '\n\t Unrecognized Action,', Action, ' No ACTION taken HERE in CModify'

    # Restore the entry into LUT with new payload
    toHash  = clientQ[PNum - 1].payload.decode('hex')[:400]
    theHash = hash(toHash)
    LUT[Prot][theHash] = (replay_name, csp)

    return clientQ, LUT, getLUT

# Server Modification:
def SModify(PcapDir, serverQ, PNum, Prot, csp, Action, Specification):
    # UDP server changes
    if Prot == 'udp':
        # print '\n\t Server packet', MPacketNum, ' Before ::',serverQ[MProtocol][csp][MPacketNum-1].payload.decode('hex')

        if 'Random' == Action:
            serverQ[Prot][csp][PNum-1].payload = \
                Randomize(serverQ[Prot][csp][PNum-1].payload)
        elif 'XOR' == Action:
            serverQ[Prot][csp][PNum-1].payload = \
            XorPayload(serverQ[Prot][csp][PNum-1].payload)
        elif 'Delete' == Action:
            # print '\n\t Server Q Before deleting ::',serverQ[MProtocol][csp]
            serverQ[Prot][csp].pop(PNum-1)
            # print '\n\t Server Q after deleting ::',serverQ[MProtocol][csp]

        elif 'ReplaceW' == Action:
            regions = Specification
            serverQ[Prot][csp][PNum-1].payload = \
                MultiReplace(serverQ[Prot][csp][PNum-1].payload, regions, '')
            # print '\n\t After ReplaceW ::',serverQ[MProtocol][csp][MPacketNum-1].payload.decode('hex')

        elif 'ReplaceR' == Action:
            regions = Specification
            rpayload = RandomLoad(PcapDir, 'Server', PNum, 'udp', csp)
            rpayload = rpayload.decode('hex')
            serverQ[Prot][csp][PNum-1].payload = \
                    MultiReplace(serverQ[Prot][csp][PNum-1].payload,regions, rpayload)

        else:
            print '\n\t Unrecognized Action,', Action, ' No ACTION taken HERE in SModify UDP'

    #TCP server changes
    else:
        if 'Random' == Action:
            serverQ[Prot][csp][PNum-1].response_list[0].payload = \
                Randomize(serverQ[Prot][csp][PNum-1].response_list[0].payload)
        elif 'XOR' == Action:
            serverQ[Prot][csp][PNum-1].response_list[0].payload = \
            XorPayload(serverQ[Prot][csp][PNum-1].response_list[0].payload)

        elif 'Delete' == Action:
            # print '\n\t Server Q Before deleting ::',serverQ[MProtocol][csp]
            serverQ[Prot][csp].pop(PNum-1)
            # print '\n\t Server Q after deleting ::',serverQ[MProtocol][csp]

        elif 'ReplaceW' == Action:
            regions = Specification
            serverQ[Prot][csp][PNum-1].response_list[0].payload = \
                MultiReplace(serverQ[Prot][csp][PNum-1].response_list[0].payload, regions, '')
            # print '\n\t After ReplaceW ::',serverQ[MProtocol][csp][MPacketNum-1].response_list[0].payload.decode('hex')

        elif 'ReplaceR' == Action:
            regions = Specification
            rpayload = RandomLoad(PcapDir, 'Server', PNum, 'tcp', csp)
            rpayload = rpayload.decode('hex')
            serverQ[Prot][csp][PNum-1].response_list[0].payload = \
                MultiReplace(serverQ[Prot][csp][PNum-1].response_list[0].payload, regions, rpayload)
            print '\r\n RRR', serverQ[Prot][csp][PNum-1].response_list[0].payload.decode('hex')

        else:
            print '\n\t Unrecognized Action,', Action, ' No ACTION taken HERE in SModify TCP'

    return serverQ


# Modify the Qs and LUT as specified
def Modification(PcapDir, clientQ, serverQ, LUT, getLUT, Prot, csp, Side, PNum, Action, Specification):

    if Side == 'Client':
        # Client modification
        clientQ, LUT, getLUT = CModify(PcapDir, clientQ, LUT, getLUT, Prot, PNum, Action, Specification)
    elif Side == 'Server':
        # Server modification
        serverQ = SModify(PcapDir, serverQ, PNum, Prot, csp, Action, Specification)

    return clientQ, serverQ, LUT, getLUT



def run(PcapDir, Side, PNum, Action, Specification):
    '''##########################################################'''

    OriginalDir = PcapDir + '/Original'
    clientPickle = ''
    serverPickle = ''

    # First load the original pickles from pcap_folder/original directory
    for file in os.listdir(OriginalDir):
        if file.endswith('client_all.pickle'):
            clientPickle = os.path.abspath(OriginalDir) + '/' + file
        elif file.endswith('server_all.pickle'):
            serverPickle = os.path.abspath(OriginalDir) + '/' + file

    serverQ, LUT, getLUT, udpServers, tcpServerPorts, replayName = \
    pickle.load(open(serverPickle, 'r'))
    clientQ, udpClientPorts, tcpCSPs, replayName = pickle.load(open(clientPickle, 'r'))

    # There should only be one protocol in the replay
    Prot = 'tcp'
    for P in serverQ.keys():
        if P != {}:
            Prot = P
    # There should only be a single csp as well
    csp = serverQ[Prot].keys()[0]

    # make modifications
    clientQ, serverQ, LUT, getLUT = Modification(PcapDir, clientQ, serverQ, LUT, getLUT, Prot, csp, Side, PNum, Action, Specification)

    # Create new pickles

    if Action == ('Random' or 'XOR'):
        print '\n\t Dumping the random payload into /random'
        RandomDump(PcapDir, clientQ, udpClientPorts, tcpCSPs, replayName, serverQ, LUT, getLUT, udpServers, tcpServerPorts)

    pickle.dump((clientQ, udpClientPorts, list(tcpCSPs), replayName)          , open((PcapDir + '/' + replayName + '_client_all.pickle'), "w" ), 2)
    pickle.dump((serverQ, LUT, getLUT, udpServers, tcpServerPorts, replayName), open((PcapDir + '/' + replayName + '_server_all.pickle'), "w" ), 2)


def main():
    PRINT_ACTION('Reading configs and args', 0)
    configs = Configs()
    configs.set('randomPayload', False)
    configs.set('pureRandom'   , False)
    configs.read_args(sys.argv)
    configs.check_for(['pcap_folder', 'PNum', 'Side', 'Action', 'Specification'])
    PcapDir = configs.get('pcap_folder')
    PNum = configs.get('PNum')
    Side = configs.get('Side')
    Action = configs.get('Action')
    Specification = configs.get('Specification')

    configs.show_all()

    run(PcapDir, Side, PNum, Action, Specification)

if __name__=="__main__":
    main()
