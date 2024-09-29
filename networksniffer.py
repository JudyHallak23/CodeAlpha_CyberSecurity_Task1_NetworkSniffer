from socket import * #to provide access to low-level networking interfaces
import struct #for conversions from python values to C structs(byte sequences)
import sys #for access to system-specific parameters
import re #for regular expression matching

#Fuction that receives data from the socket
def receiveData(s):
    data = ''
    try:
        data = s.recvfrom(65565)#receives a datagram up to 65565 bytes
    except timeout:
        data = ''
    except Exception as e:
        print(f"An error occurred: {e}", file=sys.stderr)
    return data[0] if data else None

#Function to get Type of Service(8 bit field) mapping bit values to corresponding textual meanings
def getTOS(data):
    precedence = {
        0: "Routine", 1: "Priority", 2: "Immediate", 3: "Flash",
        4: "Flash override", 5: "CRITIC/ECP", 6: "Internetwork control", 7: "Network control"
    }
    delay = {0: "Normal delay", 1: "Low delay"}
    throughput = {0: "Normal throughput", 1: "High throughput"}
    reliability = {0: "Normal reliability", 1: "High reliability"}
    cost = {0: "Normal monetary cost", 1: "Minimize monetary cost"}

    # Get bits and shift
    D = (data & 0x10) >> 4
    T = (data & 0x8) >> 3
    R = (data & 0x4) >> 2
    M = (data & 0x2) >> 1

    tabs = '\n\t\t\t'
    TOS = (precedence[data >> 5] + tabs + delay[D] + tabs + throughput[T] + tabs +
           reliability[R] + tabs + cost[M])
    return TOS

#Function to get flags (3 bits)
def getFlags(data):
    flagR = {0: "0 - Reserved bit"}
    flagDF = {0: "0 - Fragment if necessary", 1: "1 - Do not fragment"}
    flagMF = {0: "0 - Last fragment", 1: "1 - More fragments"}

    # Get bits and shift
    R = (data & 0x8000) >> 15
    DF = (data & 0x4000) >> 14
    MF = (data & 0x2000) >> 13

    tabs = '\n\t\t\t'
    flags = flagR[R] + tabs + flagDF[DF] + tabs + flagMF[MF]
    return flags

#Function to get the protocol(8 bits)
def getProtocol(protocolNr):
    try:
        with open('Protocol.txt', 'r') as protocolFile:
            protocolData = protocolFile.read()
            protocol = re.findall(r'\n' + str(protocolNr) + ' (?:.)+\n', protocolData)
            if protocol:
                protocol = protocol[0].replace("\n", "").replace(str(protocolNr), "").lstrip()
                return protocol
            else:
                return 'No such protocol.'
    except FileNotFoundError:
        return 'Protocol file not found.'

#Get the IP address of the current machine
HOST = gethostbyname(gethostname())

#Create a raw socket and bind it to the host or any port
s = socket(AF_INET, SOCK_RAW, IPPROTO_IP)
s.bind((HOST, 0))

#Include IP headers
s.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
#Enable promiscuous mode
s.ioctl(SIO_RCVALL, RCVALL_ON)

#Capture packets in an infinite loop
try:
    while True:
        data = receiveData(s)
        if data is None:
            continue

        #Get the IP header(the first 20 bytes) and unpack them
        unpackedData = struct.unpack('!BBHHHBBH4s4s', data[:20])

        version_IHL = unpackedData[0]
        version = version_IHL >> 4                   #IP version
        IHL = version_IHL & 0xF                      #Internet header length
        TOS = unpackedData[1]                        #Type of service
        totalLength = unpackedData[2]
        ID = unpackedData[3]                         #Identification
        flags = unpackedData[4]
        fragmentOffset = unpackedData[4] & 0x1FFF
        TTL = unpackedData[5]                        #Time to live(TTL)
        protocolNr = unpackedData[6]
        checksum = unpackedData[7]
        sourceAddress = inet_ntoa(unpackedData[8])
        destinationAddress = inet_ntoa(unpackedData[9])

        # Print the captured information for each packet
        print(f"\nAn IP packet with the size {totalLength} was captured.")
        print("Raw data:", data)
        print("\nParsed data")
        print(f"Version:\t\t{version}")
        print(f"Header Length:\t\t{IHL * 4} bytes")
        print(f"Type of Service:\t{getTOS(TOS)}")
        print(f"Length:\t\t\t{totalLength}")
        print(f"ID:\t\t\t{hex(ID)} ({ID})")
        print(f"Flags:\t\t\t{getFlags(flags)}")
        print(f"Fragment offset:\t{fragmentOffset}")
        print(f"TTL:\t\t\t{TTL}")
        print(f"Protocol:\t\t{getProtocol(protocolNr)}")
        print(f"Checksum:\t\t{checksum}")
        print(f"Source:\t\t\t{sourceAddress}")
        print(f"Destination:\t\t{destinationAddress}")
        print("Payload:\n", data[20:])

except KeyboardInterrupt:
    # Gracefully disable promiscuous mode
    s.ioctl(SIO_RCVALL, RCVALL_OFF)
    print("\nStopped packet capture.")
