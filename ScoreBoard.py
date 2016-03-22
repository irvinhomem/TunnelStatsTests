from MetaCapLibrary import MetaCapLibrary
from PacketAnalyzer import PacketAnalyzer
from PacketDigester import PacketDigester

import logging

class ScoreBoard(object):

    def __init__(self):
        #Configure Logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        #logger.setLevel(logging.INFO)
        self.logger.setLevel(logging.DEBUG)
        #logger.setLevel(logging.WARNING)

        self.handler = logging.FileHandler('scoreboard.log')
        self.handler.setLevel(logging.INFO)

        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        self.handler.setFormatter(formatter)

        self.grndTruthLib_list = []
        self.testSampleLib_list = []

        self.stats_list = ['','','','','','','']
        self.scoreDict = dict(stat_measure='', av_score=0.0, grndLabel='')

    def load_ground_truths(self):
        # Load GroundTruth library / base (Filtered)
        http_grndTruthLib = MetaCapLibrary()
        http_grndTruthLib.load_specific_proto_from_base('http','http')
        self.grndTruthLib_list.append(http_grndTruthLib)

        ftp_grndTruthLib = MetaCapLibrary()
        ftp_grndTruthLib.load_specific_proto_from_base('ftp', 'ftp')
        self.grndTruthLib_list.append(ftp_grndTruthLib)

        self.logger.debug("HTTP Ground Lib Len: %i " % len(http_grndTruthLib.get_packet_library()))
        self.logger.debug("FTP Ground Lib Len: %i " % len(ftp_grndTruthLib.get_packet_library()))
        self.logger.debug("Ground Lib List Len: %i " % len(self.grndTruthLib_list))

    def load_test_sample_pcaps(self):
        # Load Test-PCAP library / base (Filtered)
        HTovDns_testLib = MetaCapLibrary()
        HTovDns_testLib.load_specific_proto_from_base('http-test','dns')
        self.testSampleLib_list.append(HTovDns_testLib)

        FTovDNS_testLib = MetaCapLibrary()
        FTovDNS_testLib.load_specific_proto_from_base('ftp-test','dns')
        self.testSampleLib_list.append(FTovDNS_testLib)

        self.logger.debug("HTTP Ground Lib Len: %i " % len(HTovDns_testLib.get_packet_library()))
        self.logger.debug("FTP Ground Lib Len: %i " % len(FTovDNS_testLib.get_packet_library()))
        self.logger.debug("Ground Lib List Len: %i " % len(self.testSampleLib_list))

    def getGrndTruthLib_list(self):
        return self.grndTruthLib_list

    def getTestSampleLib_list(self):
        return self.testSampleLib_list

    def getStats_list(self):
        return self.stats_list

    def calcAvgStatScores(stat_measure_name, test_cap, grndtruth_cap):
        pktDgstr = PacketDigester()
        pktAnlyzr = PacketAnalyzer()
        grnd_Req_Entropy_Seq = None

        if grndtruth_cap.get_proto_label() == 'http':
            grnd_Req_Entropy_Seq = grndtruth_cap.getHttpReqEntropy()    # httpMcap.get_ip_pkt_http_req_entropy()    # getHttpReqEntropy     # getCompressedHttpReqEntropy
        elif grndtruth_cap.get_proto_label() == 'ftp':
            grnd_Req_Entropy_Seq = grndtruth_cap.getFtpReqEntropy()      # ftpMcap.get_ip_pkt_ftp_req_entropy()      # getFtpReqEntropy      # getCompressedFtpReqEntropy

        # Score against ** ANY ** GIVEN GROUND PROTOCOL
        avg_score_to_GRND, score_vals = pktAnlyzr.calcStatMeasureAvg(
            stat_measure_name,
            pktDgstr.getPopulationLists("ANY",
                test_cap.getDnsReqDataEntropy_upstream(),   # getDnsPktEntropy
                grnd_Req_Entropy_Seq),
            1000)

        # # Score against ** HTTP **
        # avg_score_to_HTTP, score_vals = pktAnlyzr.calcStatMeasureAvg(
        #     stat_measure_name,
        #     pktDgstr.getPopulationLists("HTTP",
        #         test_cap.getDnsReqDataEntropy_upstream(),   # getDnsPktEntropy
        #         grndtruth_cap.getHttpReqEntropy()),    # httpMcap.get_ip_pkt_http_req_entropy()    # getHttpReqEntropy     # getCompressedHttpReqEntropy
        #     1000)
        #
        # # Score against ** FTP **
        # avg_score_to_FTP, score_vals = pktAnlyzr.calcStatMeasureAvg(
        #     stat_measure_name,
        #     pktDgstr.getPopulationLists("FTP",
        #         test_cap.getDnsReqDataEntropy_upstream(),       #getDnsPktEntropy
        #         grndtruth_cap.getFtpReqEntropy()),
        #     1000)
        # return avg_score_to_HTTP, avg_score_to_FTP
        return stat_measure_name, avg_score_to_GRND, grndtruth_cap.get_proto_label()

myScoreB = ScoreBoard()

# Load GroundTruth library / base (Filtered)
myScoreB.load_ground_truths()

# Load Test-PCAP library / base (Filtered)
myScoreB.load_test_sample_pcaps()

# Generally: Pick a specific test-PCAP file and compare it against the Ground Truth Base files / Statistics
for idx_test, sample_lib in enumerate(myScoreB.testSampleLib_list):
    for mcap_test in enumerate(sample_lib[idx_test]):
        for idx_grnd, grnd_lib in enumerate(myScoreB.grndTruthLib_list):
            for mcap_grnd in enumerate(grnd_lib[idx_grnd]):
                for stat in myScoreB.getStats_list():
                    myScoreB.scoreDict = myScoreB.calcAvgStatScores(stat, mcap_test, mcap_grnd)


