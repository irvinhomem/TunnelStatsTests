from PacketAnalyzer import PacketAnalyzer
from MetaPacketCap import MetaPacketCap
from MetaCapLibrary import MetaCapLibrary
from PacketDigester import PacketDigester
from terminaltables import AsciiTable

import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
# Collect Packet Captures to Analyze
# HTTP Base (HTTP Ground Truth)
#httpMcap = MetaPacketCap("../scapy_tutorial/NewPcaps/TunnelCaps_2011/HTTP.pcap", 'http')
httpMcap = MetaPacketCap("../scapy_tutorial/NewPcaps/TunnelCaps_2011/HTTP.pcap", 'http')
# httpOvrDnsMetaCap = MetaPacketCap("../scapy_tutorial/NewPcaps/TunnelCaps_2011/HTTPoverDNS.pcap")

ftpMcap = MetaPacketCap("../scapy_tutorial/NewPcaps/TunnelCaps_2011/FTP.pcap", 'ftp')
#ftpMcap = MetaPacketCap("../scapy_tutorial/NewPcaps/TunnelCaps_2016/FTP/FTP-Audio/FTP-Audio2-dl-Mp3.pcapng", 'ftp')
# ftpOvrDnsMetaCap = MetaPacketCap("../scapy_tutorial/NewPcaps/TunnelCaps_2011/FTPoverDNS.pcap")

# Test Sample (**Stuff Tunnelled over DNS**):
#x_over_DnsTun = MetaPacketCap("../scapy_tutorial/NewPcaps/TunnelCaps_2011/HTTPoverDNS.pcap", 'http')
#x_over_DnsTun = MetaPacketCap("../scapy_tutorial/NewPcaps/TunnelCaps_2016/HTTP/amazon.com/amazon.com-2016-02-25-T190359-HTovDNS-incog.pcapng", 'http')
#x_over_DnsTun = MetaPacketCap("../scapy_tutorial/NewPcaps/TunnelCaps_2016/HTTP/bbc.co.uk/bbc.co.uk-2016-02-25-T190746-HTovDNS-incog.pcapng", 'http')
#x_over_DnsTun = MetaPacketCap("../scapy_tutorial/NewPcaps/TunnelCaps_2016/HTTP/craigslist.org/craigslist.org-2016-02-25-T185633-HTovDNS-incog.pcapng", 'http')
#x_over_DnsTun = MetaPacketCap("../scapy_tutorial/NewPcaps/TunnelCaps_2011/FTPoverDNS.pcap", 'ftp')
#x_over_DnsTun = MetaPacketCap("../scapy_tutorial/NewPcaps/TunnelCaps_2016/FTP/FTP-PlainTxT/FTovDNS-TextFile-dl-small.pcapng", 'ftp')
#x_over_DnsTun = MetaPacketCap("../scapy_tutorial/NewPcaps/TunnelCaps_2016/FTP/FTP-PlainTxT/FTovDNS-TextFile2-dl-Big.pcapng", 'ftp')
#x_over_DnsTun = MetaPacketCap("../scapy_tutorial/NewPcaps/TunnelCaps_2016/FTP/FTP-Audio/FTP-Audio2-dl-Mp3.pcapng", 'ftp')
x_over_DnsTun = MetaPacketCap("../scapy_tutorial/NewPcaps/TunnelCaps_2016/FTP/FTP-PDF/FTovDNS-PDF-dl-Big.pcapng", 'ftp')


print("Pcaps Loaded and Initialized ... ")

pktDgstr = PacketDigester()
pktAnlyzr = PacketAnalyzer()

def calcAvgStatScores(stat_measure_name):

    # Score against ** HTTP **
    avg_score_to_HTTP, score_vals = pktAnlyzr.calcStatMeasureAvg(
        stat_measure_name,
        pktDgstr.getPopulationLists("HTTP",
            x_over_DnsTun.getDnsReqDataEntropy_upstream(),   # getDnsPktEntropy
            httpMcap.getHttpReqEntropy()),    # httpMcap.get_ip_pkt_http_req_entropy()    # getHttpReqEntropy     # getCompressedHttpReqEntropy
        1000)

    # Score against ** FTP **
    avg_score_to_FTP, score_vals = pktAnlyzr.calcStatMeasureAvg(
        stat_measure_name,
        pktDgstr.getPopulationLists("FTP",
            x_over_DnsTun.getDnsReqDataEntropy_upstream(),       #getDnsPktEntropy
            ftpMcap.getFtpReqEntropy()),      # ftpMcap.get_ip_pkt_ftp_req_entropy()      # getFtpReqEntropy      # getCompressedFtpReqEntropy
        1000)
    return avg_score_to_HTTP, avg_score_to_FTP

def simple_predictor(score_result, stat_measure):
    # score_result[0] is avg_score_to_HTTP
    # score_result[1] is avg_score_to_FTP
    if stat_measure == "KL-Divergence":
        if score_result[0] < score_result[1]:
            return 'HT'
        else:
            return 'FT'
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
            return 'HT'
        else:
            return 'FT'
    elif stat_measure == "MeanDiff":
        if abs(score_result[0]) < abs(score_result[1]):
            return 'HTTP'
        else:
            return 'FTP'
    elif stat_measure == "KendallTau":
        if abs(score_result[0]) < abs(score_result[1]):
            return 'HTTP'
        else:
            return 'FTP'
    elif stat_measure == "StdDevDiff":
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
meanDiff_score = calcAvgStatScores("MeanDiff")
stdDevDiff_score = calcAvgStatScores("StdDevDiff")
kendalltau_score = calcAvgStatScores('KendallTau')
anderson_kSamp_score = None
bhattacharya_avg_score = ''
mahalanobis_avg_score = ''
try:
    anderson_kSamp_score = calcAvgStatScores("Anderson_kSamp")  # Throws overflow error for some sets
except Exception as e:
    logger.debug('Error with Anderson-kSamp: %s' % str(e))
    logger.debug('Error with Anderson-kSamp: %s' % repr(e))
    anderson_kSamp_score = []
    anderson_kSamp_score.append(0.0)
    anderson_kSamp_score.append(0.0)


klDiv_res = simple_predictor(kl_div_avg_score, "KL-Divergence")
spearmanr_res = simple_predictor(spearmanr_avg_score, "SpearmanR")
pearson_res = simple_predictor(pearson_avg_score, "Pearson")
ksimrnov_2samp_res = simple_predictor(ksmirnov_2samp_score, "2Samp_KSmirnov")
meanDiff_res = simple_predictor(meanDiff_score, "MeanDiff")
kendalltau_res = simple_predictor(kendalltau_score, "KendallTau")
stdDevDiff_res = simple_predictor(stdDevDiff_score, "StdDevDiff")
bhattacharya_res = ''
mahalanobis_res = ''

table_data = [
    ['Protocol/Stat','KL-Div','SpearmanR', 'Pearson', 'KSmirnov-2Samp', 'MeanDiff', 'KendallTau', 'Anderson-kSamp','Std-Dev-Diff',
     'Bhattacharya', 'Mahalanobis'],
    ['Against HTTP: ', str(kl_div_avg_score[0]), str(spearmanr_avg_score[0]), str(pearson_avg_score[0]),
     str(ksmirnov_2samp_score[0]), str(meanDiff_score[0]), str(kendalltau_score[0]), str(anderson_kSamp_score[0]), str(stdDevDiff_score[0]), str(''), str('')],
    ['Against FTP: ', str(kl_div_avg_score[1]), str(spearmanr_avg_score[1]), str(pearson_avg_score[1]),
     str(ksmirnov_2samp_score[1]), str(meanDiff_score[1]), str(kendalltau_score[1]), str(anderson_kSamp_score[1]), str(stdDevDiff_score[1]), str(''), str('')],
    ['Difference: ', str(kl_div_avg_score[0] - kl_div_avg_score[1]), str(spearmanr_avg_score[0]- spearmanr_avg_score[1]),
     str(pearson_avg_score[0] - pearson_avg_score[1]), str(ksmirnov_2samp_score[0] - ksmirnov_2samp_score[1]),
     str(meanDiff_score[0] - meanDiff_score[1]), str(kendalltau_score[0] - kendalltau_score[1]), str(''),
     str(stdDevDiff_score[0] - stdDevDiff_score[1]), str(''), str('')],
    ['Prediction: ', klDiv_res, spearmanr_res, pearson_res, ksimrnov_2samp_res, meanDiff_res, kendalltau_res, str(''), str(''),
     bhattacharya_res, mahalanobis_res]
]
myTable = AsciiTable(table_data)
myTable.inner_footing_row_border = True
print(myTable.table)



