import logging

LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
DATE_FORMAT = "%Y/%m/%d-%H:%M:%S"

logging.basicConfig(level=logging.DEBUG, format=LOG_FORMAT)

def get_logger(name=None):
    return logging.getLogger(name or __name__)
