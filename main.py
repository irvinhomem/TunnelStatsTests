from PacketAnalyzer import PacketAnalyzer
from MetaPacketCap import MetaPacketCap
from PacketDigester import PacketDigester


#if __name__ == "main":
# 1. Read pcap file
# 2. Get specific entropy function,
# 3. "do plot"

# Collect Packet Captures to Analyze
httpMcap = MetaPacketCap("../scapy_tutorial/NewPcaps/TunnelCaps_2011/HTTP.pcap")
httpOvrDnsMetaCap = MetaPacketCap("../scapy_tutorial/NewPcaps/TunnelCaps_2011/HTTPoverDNS.pcap")
print("Initialized ... ")

# Get basic measurements set
#httpMcap.getHttpReqEntropy()
#httpOvrDnsMetaCap.getDnsPktEntropy()

#httpMcap.getHttpReEntropy()
#httpOvrDnsMetaCap

pktDgstr = PacketDigester()
# packetPops = pktDgstr.getPopulationLists(httpMcap.getHttpReqEntropy(), httpOvrDnsMetaCap.getDnsPktEntropy())
# print("Packet Population Sequences Type: ", type(len(packetPops['testSeq'])))
# print("Packet Population Sequences len: ", len(packetPops['testSeq']))

pktAnlyzr = PacketAnalyzer()

avg20Samples = pktAnlyzr.calcStatMeasureAvg(
    "KL-Divergence",
    pktDgstr.getPopulationLists(
        httpOvrDnsMetaCap.getDnsPktEntropy(),
        httpMcap.getHttpReqEntropy()),
    20)

print("Kullback-Leibler Distance Average of 20 Sampling Rounds: ", avg20Samples)

## Calculate Kullback-Leibler Divergence
#compKsResult = httpCapture.calcKLDistance(
#    httpCapture.getTwoEquiLenSamples(httpOvrDnsCap.getDnsPktEntropy(), httpCapture.getHttpReqEntropy()))
#print("Kullback-Leibler Distance result: ", compKsResult)

# Calculate Averaged Kullback-Leibler Divergence
# avg20Samples = httpCapture.calcStatMeasureAvg(
#     "KL-Divergence",
#     httpCapture.getTwoEquiLenSamples(
#         httpOvrDnsCap.getDnsPktEntropy(),
#         httpCapture.getHttpReqEntropy()),
#     20)
#
# print("Kullback-Leibler Distance Average of 20 Tests: ", avg20Samples)

## Calculcate Spearman Ranked coefficient of correlation
#spearmanCoeff = httpCapture.calcSpearman(httpOvrDnsCap.getHttpReqEntropy(),httpCapture.getHttpReqEntropy())
#print("Spearman Correlation Coefficient: ", spearmanCoeff)

##
#httpCapture.doSampleEqualizer(httpOvrDnsCap.getDnsPktEntropy(), httpCapture.getHttpReqEntropy())

# httpCapture.doPlot("HTTP Request Entropy", "Packet Sequence (Time)", "Byte (Char) Entropy per packet")