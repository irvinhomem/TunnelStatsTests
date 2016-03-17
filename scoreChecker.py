from PacketAnalyzer import PacketAnalyzer
from MetaPacketCap import MetaPacketCap
from PacketDigester import PacketDigester
from terminaltables import AsciiTable

# Collect Packet Captures to Analyze
# HTTP Base (HTTP Ground Truth)
httpMcap = MetaPacketCap("../scapy_tutorial/NewPcaps/TunnelCaps_2011/HTTP.pcap", 'http')
# httpOvrDnsMetaCap = MetaPacketCap("../scapy_tutorial/NewPcaps/TunnelCaps_2011/HTTPoverDNS.pcap")

ftpMcap = MetaPacketCap("../scapy_tutorial/NewPcaps/TunnelCaps_2011/FTP.pcap", 'ftp')
# ftpOvrDnsMetaCap = MetaPacketCap("../scapy_tutorial/NewPcaps/TunnelCaps_2011/FTPoverDNS.pcap")

# Test Sample:
#x_over_DnsTun = MetaPacketCap("../scapy_tutorial/NewPcaps/TunnelCaps_2011/HTTPoverDNS.pcap", 'http')
x_over_DnsTun = MetaPacketCap("../scapy_tutorial/NewPcaps/TunnelCaps_2011/FTPoverDNS.pcap", 'ftp')

print("Pcaps Loaded and Initialized ... ")

pktDgstr = PacketDigester()
pktAnlyzr = PacketAnalyzer()

def calcAvgStatScores(stat_measure_name):

    # Score against ** HTTP **
    avg_score_to_HTTP, score_vals = pktAnlyzr.calcStatMeasureAvg(
        stat_measure_name,
        pktDgstr.getPopulationLists("HTTP",
            x_over_DnsTun.getDnsPktEntropy(),
            httpMcap.getHttpReqEntropy()),    # httpMcap.get_ip_pkt_http_req_entropy()    # getHttpReqEntropy
        1000)

    # Score against ** FTP **
    avg_score_to_FTP, score_vals = pktAnlyzr.calcStatMeasureAvg(
        stat_measure_name,
        pktDgstr.getPopulationLists("FTP",
            x_over_DnsTun.getDnsPktEntropy(),
            ftpMcap.getFtpReqEntropy()),      # ftpMcap.get_ip_pkt_ftp_req_entropy()      # getFtpReqEntropy
        1000)
    return avg_score_to_HTTP, avg_score_to_FTP

def simple_predictor(score_result, stat_measure):
    # score_result[0] is avg_score_to_HTTP
    # score_result[1] is avg_score_to_FTP
    if stat_measure == "KL-Divergence":
        if score_result[0] < score_result[1]:
            return 'HTTP'
        else:
            return 'FTP'
    elif stat_measure == "SpearmanR":
        if abs(score_result[0]) < abs(score_result[1]):
            return 'HTTP'
        else:
            return 'FTP'
    elif stat_measure == "Pearson":
        if abs(score_result[0]) < abs(score_result[1]):
            return 'HTTP'
        else:
            return 'FTP'
    elif stat_measure == "2Samp_KSmirnov":
        if abs(score_result[0]) < abs(score_result[1]):
            return 'HTTP'
        else:
            return 'FTP'
    elif stat_measure == "Bhatta":
        if abs(score_result[0]) < abs(score_result[1]):
            return 'HTTP'
        else:
            return 'FTP'
    elif stat_measure == "Hellinger":
        if abs(score_result[0]) < abs(score_result[1]):
            return 'HTTP'
        else:
            return 'FTP'
    elif stat_measure == "Mahalanobis":
        if abs(score_result[0]) < abs(score_result[1]):
            return 'HTTP'
        else:
            return 'FTP'
    else:
        print("Undefined Stat Measure: ", stat_measure)



kl_div_avg_score = calcAvgStatScores("KL-Divergence")
spearmanr_avg_score = calcAvgStatScores("SpearmanR")
pearson_avg_score = calcAvgStatScores("Pearson")
ksmirnov_2samp_score = calcAvgStatScores("2Samp_KSmirnov")
bhattacharya_avg_score = ''
mahalanobis_avg_score = ''

klDiv_res = simple_predictor(kl_div_avg_score, "KL-Divergence")
spearmanr_res = simple_predictor(spearmanr_avg_score, "SpearmanR")
pearson_res = simple_predictor(pearson_avg_score, "Pearson")
ksimrnov_2samp_res = simple_predictor(ksmirnov_2samp_score, "2Samp_KSmirnov")
bhattacharya_res = ''
mahalanobis_res = ''

table_data = [
    ['Protocol/Stat','KL-Div','SpearmanR', 'Pearson', 'KSmirnov-2Samp', 'Bhattacharya', 'Mahalanobis'],
    ['Against HTTP: ', str(kl_div_avg_score[0]), str(spearmanr_avg_score[0]), str(pearson_avg_score[0]), str(ksmirnov_2samp_score[0]), str(''), str('')],
    ['Against FTP: ', str(kl_div_avg_score[1]), str(spearmanr_avg_score[1]), str(pearson_avg_score[1]), str(ksmirnov_2samp_score[1]), str(''), str('')],
    ['Difference: ', str(kl_div_avg_score[0] - kl_div_avg_score[1]), str(spearmanr_avg_score[0]- spearmanr_avg_score[1]),
     str(pearson_avg_score[0] - pearson_avg_score[1]), str(pearson_avg_score[0] - pearson_avg_score[1]), str(''), str('')],
    ['Prediction: ', klDiv_res, spearmanr_res, pearson_res, ksimrnov_2samp_res, bhattacharya_res, mahalanobis_res]
]
myTable = AsciiTable(table_data)
myTable.inner_footing_row_border = True
print(myTable.table)

# print("Scores:" )
# print("Against HTTP: ")
# print("\t KL-Div score: ", avgKLd20_to_HTTP)
# print("Against FTP: ")
# print("\t KL-Div score: ", avgKLd20_to_FTP)
# print("Difference: ", avgKLd20_to_HTTP - avgKLd20_to_FTP)

