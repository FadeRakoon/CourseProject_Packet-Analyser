#!/bin/python3
#Project Group Members
#ruwan_amarakoon - FadeRakoon [GitHub]
#david_rodney - RedBrickRants [GitHub]

import math
import os
import random
import re
import sys


def makePacket(srcIP, dstIP, length, prt, sp, dp, sqn, pld):
    """
    Constructs a Packet as a tuple with a tag 'PK'.
    
    Args:
        srcIP (str): Source IP address.
        dstIP (str): Destination IP address.
        length (int): Length of the packet.
        prt (str): Protocol.
        sp (int): Source port.
        dp (int): Destination port.
        sqn (int): Sequence number.
        pld (str): Payload.
    
    Returns:
        tuple: A packet represented as a tuple starting with the tag 'PK'.
    """
    return ('PK', srcIP, dstIP, [length, str(prt), [sp, dp], sqn, pld])


def getPacketSrc(pkt):
    """ Returns the Source IP of the packet provided """
    return pkt[1]


def getPacketDst(pkt):
    """ Returns the Destination IP of the packet provided """
    return pkt[2]


def getPacketDetails(pkt):
    """ Provides the details of the packet provided """
    return pkt[3]


def isPacket(pkt):
    """ Ensures that the object is a packet by checking its type, the PK tag, and the length of the object """
    return isinstance(pkt, tuple) and pkt[0] == 'PK' and len(pkt) == 4


def isEmptyPkt(pkt):
    """ Simply checks to see if the packet is empty and returns true if it is, and false if it isn't. """
    return pkt == []

#pt2 starts below

def getLength(pkt):
    """ Returns the length of the provided packet """
    return pkt[3][0]


def getProtocol(pkt):
    """ Returns the packet's protocol """
    return pkt[3][1]


def getSrcPort(pkt):
    """ Returns the packet's source port """
    return pkt[3][2][0]


def getDstPort(pkt):
    """ Returns the packet's destination port """
    return pkt[3][2][1]


def getSqn(pkt):
    """ Returns the sequence number of the packet """
    return pkt[3][3]


def getPayloadSize(pkt):
    """ Returns the payload of the packet """
    return pkt[3][4]

#pt 3 starts below

def flowAverage(pkt_list):
    """ 
    Calculate the total payload size and count, 
    then return packets with payload sizes greater than the average 
    """
    Pldsum = 0
    count = 0
    
    for pkt in pkt_list:
        payload_size = getPayloadSize(pkt)  # Assuming payload is at pkt[3][4] based on the tuple structure
        Pldsum += payload_size
        count += 1

    avg = Pldsum / count  # Calculate average payload size
    avg = round(avg, 2)
    above_average_packets = list(filter(lambda pkt: getPayloadSize(pkt) > avg, pkt_list))

    return above_average_packets


def suspPort(pkt):
    """ Checks port compliance """
    src = getSrcPort(pkt)  # Extract source port
    dst = getDstPort(pkt)  # Extract destination port

    if src > 500 or dst > 500:
        return True  # Suspicious port detected
    return False  # No suspicious ports


def suspProto(pkt):
    """ Checks protocol compliance """
    protocol = getProtocol(pkt)  # Get protocol of the provided packet
    if protocol not in ProtocolList:  # Check if protocol is in the predefined list
        return True
    return False


def ipBlacklist(pkt):
    """ Checks if the packet's IP is in the blacklist """
    ip = getPacketSrc(pkt)
    if ip in IpBlackList:
        return True
    return False

#pt4 starts below

def calScore(pkt):
    """
    Calculates the score for a packet based on various metrics.
    """
    score = 0
    
    # Check average packet size
    avg_pkt_list = flowAverage(pkt_list)  # Get list of packets above average
    if pkt in avg_pkt_list:
        score += 3.56

    # Check suspicious protocol
    if suspProto(pkt):
        score += 2.74

    # Check suspicious ports
    if suspPort(pkt):
        score += 1.45

    # Check if IP is in the blacklist
    if ipBlacklist(pkt):
        score += 10

    return round(score, 2)


def makeScore(pkt_list):
    """
    Takes a list of packets and returns a list with the tag 'SCORE' followed by the packets, each with a respective score.
    """
    score_list = ["SCORE", []]
    for pkt in pkt_list:
        score = calScore(pkt)  # Calculate the score for each packet
        score_list[1].append((pkt, score))  # Append the packet with its score
    return score_list


def addPacket(ScoreList, pkt):
    """
    Adds a packet to the ScoreList after calculating its score.
    """
    if not isScore(ScoreList):
        raise ValueError("Invalid ScoreList")
    
    # Calculate the score for the packet using calScore function
    score_details = calScore(pkt)
    
    # Append the packet along with its score details to the ScoreList
    ScoreList[1].append((pkt, score_details))


def getSuspPkts(ScoreList):
    """
    Returns a list of suspicious packets based on score list.
    """
    lst = []
    for pkt, score_details in ScoreList[1]:
        if score_details > 5:
            lst.append(pkt)
    return lst


def getRegulPkts(ScoreList):
    """
    Takes a ScoreList and returns a list of all regular packets (those with total score 0).
    
    Args:
        ScoreList (list): The score list containing packets and their scores.
    
    Returns:
        list: A list of regular packets.
    """
    if not isScore(ScoreList):
        raise ValueError("Invalid score list")
    
    regular_packets = []
    
    # Iterate through the ScoreList (skipping the first element which is the "SCORE" tag)
    for pkt, score_details in ScoreList[1]:
        if score_details <= 5:  # Regular packet has total score of 0
            regular_packets.append(pkt)
    
    return regular_packets


def isScore(ScoreList):
    """
    Checks if the input list is a valid Score list.
    
    Args:
        ScoreList (list): The list to check.
    
    Returns:
        bool: True if the list is a valid Score list, False otherwise.
    """
    return isinstance(ScoreList, list) and len(ScoreList) == 2 and ScoreList[0] == "SCORE" and isinstance(ScoreList[1], list)


def isEmptyScore(ScoreList):
    """
    Checks if the input Score list is empty (i.e., has no packets).
    
    Args:
        ScoreList (list): The list to check.
    
    Returns:
        bool: True if the ScoreList has no packets, False otherwise.
    """
    return isScore(ScoreList) and len(ScoreList[1]) == 0


#pt5 starts below

def makePacketQueue():
    """returns a packet queue"""
    return ("PQ",[])
    
def contentsQ(q):
    """returns the contents of a packet queue"""
    return q[1]
    
def frontPacketQ(q):
    """returns the front of the packet queue"""
    return contentsQ(q)[0]

def addToPacketQ(pkt,q):
    """adds a packet to the back of the packet queue"""
    if isPacketQ(q):
        pos = get_pos(pkt,contentsQ(q))
        contentsQ(q).insert(pos,pkt)
    
def get_pos(pkt,lst):
    if (lst == []):
        return 0
    elif getSqn(pkt) < getSqn(lst[0]):
        return 0 + get_pos(pkt,[])
    else:
        return 1 + get_pos(pkt,lst[1:])
            
def removeFromPacketQ(q):
    """removes a packet from the front of the packet queue"""
    if not isEmptPacketQ(q) and isPacketQ(q):
        contentsQ(q).pop(0)
    
def isPacketQ(q):
    """checks if an object is a packet queue"""
    return isinstance(q,tuple) and q[0] == "PQ" and len(q)==2

def isEmptPacketQ(q):
    """checks if a packet queue is empty"""
    return contentsQ(q)==[]

#pt6 starts below

def makePacketStack():
    """returns a packet stack"""
    return ("PS",[])

def contentsStack(stk):
    """returns the contents of a packet stack"""
    return stk[1]

def topProjectStack (stk):
    """returns the top of a packet stack"""
    return contentsStack(stk)[len(contentsStack(stk))-1]

def pushProjectStack(pkt,stk):
    """pushes a packet to the packet stack"""
    if isPKstack(stk):
        contentsStack(stk).append(pkt)
    
def popPickupStack(stk):
    """pops a packet from the packet stack"""
    if isPKstack(stk) and not isEmptyPKStack(stk):
        contentsStack(stk).pop()

def isPKstack(stk):
    """Checks if stack is a packet stack"""
    return isinstance(stk,tuple) and stk[0] == "PS" and len(stk) == 2

def isEmptyPKStack(stk):
    """Checks if the packet stack is empty"""
    return contentsStack(stk)==[]

#pt7 starts below

def sortPackets(scoreList,stack,queue):
    """sorts packets into the forwarding queue or the death stack based on suspicion score"""
    SusPkts = getSuspPkts(scoreList) #list of sus packets
    RegulPkts = getRegulPkts(scoreList) # list of reguglar packets
    
    #scoreList[1]==actual data stored in scoreList data structure
    #scoreList[0]=="score" tag used to define scoreList data structure
    for i in scoreList[1]:
        # i => (packet,score) from scoreList[1] 
        pkt = i[0] 
        #check if packet is in the list of sus packets
        if pkt in SusPkts:
            #if it is sus packet, push to death stack
            pushProjectStack(pkt,stack)
        #if packet isnt a sus packet, check if it is in list of regular packets
        elif pkt in RegulPkts:
            #if it is regular packet, push to forwarding stack
            addToPacketQ(pkt,queue)

# part8 starts below

def analysePackets(packet_List):
    """main driver function of program"""
    global pkt_list #make plt_list globally available
    
    #converts packet_List into a list of packet ADT's
    #*pkt passes a tuple of arguments as an arbitrary argument
    pkt_list = [makePacket(*pkt) for pkt in packet_List] #populate pkt_list
    scoreList = makeScore(pkt_list) #generate scoreList based on pkt_list   
    stk = makePacketStack() #initialize death stack
    q = makePacketQueue() # initialize forwarding queue
    sortPackets(scoreList,stk,q) #sort the packets into death stack and forwarding queue
    return q #return forwarding queue
    

#main function provided in original project instructions
if __name__ == '__main__':
    fptr = open(os.environ['OUTPUT_PATH'], 'w')

    first_multiple_input = input().rstrip().split()
    
    srcIP = str(first_multiple_input[0])
    dstIP = str(first_multiple_input[1])
    length = int(first_multiple_input[2])
    prt = str(first_multiple_input[3])
    sp = int(first_multiple_input[4])
    dp = int(first_multiple_input[5])
    sqn = int(first_multiple_input[6])
    pld = int(first_multiple_input[7])
    
    ProtocolList = ["HTTPS","SMTP","UDP","TCP","DHCP","IRC"]
    IpBlackList = ["213.217.236.184","149.88.83.47","223.70.250.146","169.51.6.136","229.223.169.245"]
    
    #input list
    packet_List = [(srcIP, dstIP, length, prt, sp, dp, sqn, pld), ("111.202.230.44","62.82.29.190",31,"HTTP",80,20,1562436,338),("222.57.155.164","50.168.160.19",22,"UDP",790,5431,1662435,812),("333.230.18.207","213.217.236.184",56,"IMCP",501,5643,1762434,3138), ("444.221.232.94","50.168.160.19",1003,"TCP",4657,4875,1962433,428),("555.221.232.94","50.168.160.19",236,"HTTP",7753,5724,2062432,48)]
    
    #output
    fptr.write('Forward Packets => ' + str(analysePackets(packet_List)) + '\n')
    
    fptr.close()