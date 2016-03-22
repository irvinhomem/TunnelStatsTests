from MetaCapLibrary import MetaCapLibrary
import logging

#Configure Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

handler = logging.FileHandler('scoreboard.log')
handler.setLevel(logging.INFO)

formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)


# Load GroundTruth library / base (Filtered)
http_grndTruthLib = MetaCapLibrary()
http_grndTruthLib.load_specific_proto_from_base('http','http')

ftp_grndTruthLib = MetaCapLibrary()
ftp_grndTruthLib.load_specific_proto_from_base('ftp', 'ftp')

logger.info("HTTP Ground Lib Len: %i " % len(http_grndTruthLib.get_packet_library()))
logger.info("FTP Ground Lib Len: %i " % len(ftp_grndTruthLib.get_packet_library()))

# Load Test-PCAP library / base (Filtered)

# Generally: Pick a specific test-PCAP file and compare it against the Ground Truth Base files / Statistics

#for mcap in