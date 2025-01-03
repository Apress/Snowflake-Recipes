from logging import getLogger
import snowflake.connector
from snowflake.ingest import SimpleIngestManager
from snowflake.ingest import StagedFile
from snowflake.ingest.utils.uris import DEFAULT_SCHEME
from datetime import timedelta
from requests import HTTPError
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PrivateFormat
from cryptography.hazmat.primitives.serialization import NoEncryption
import time
import datetime
import logging

logging.basicConfig(
        filename='/tmp/ingest.log',
        level=logging.DEBUG)
logger = getLogger(__name__)

# If you generated an encrypted private key, implement this method to return
# the passphrase for decrypting your private key.
# instead of hardcoding get the value from environment variable or config files: os.environ['PRIVATE_KEY_PASSPHRASE']
def get_private_key_passphrase():
  return 'eipe' 


with open("/Users/johneipe/rsa_key_snow.p8", 'rb') as pem_in:
  pemlines = pem_in.read()
  private_key_obj = load_pem_private_key(pemlines,
  get_private_key_passphrase().encode(),
  default_backend())

private_key_text = private_key_obj.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode('utf-8')
# Assume the public key has been registered in Snowflake:
# private key in PEM format

ingest_manager = SimpleIngestManager(account='bwbyxua-xxxxx',
                                     host='bwbyxua-xxxxx.snowflakecomputing.com',
                                     user='jeipe',
                                     pipe='raw.retail.sfdemo_pipe_api_trigger',
                                     private_key=private_key_text)


# List of files, but wrapped into a class
staged_file_list = [
  StagedFile('customer_sample.csv', None),  
  # the second parameter is file size but it is optional but recommended, pass None if not available
]

try:
    resp = ingest_manager.ingest_files(staged_file_list)
except HTTPError as e:
    logger.error(e)# HTTP error, may need to retry
    exit(1)

# This means Snowflake has received file and will start loading
assert(resp['responseCode'] == 'SUCCESS')

# Needs to wait for a while to get result in history
while True:
    history_resp = ingest_manager.get_history()

    if len(history_resp['files']) > 0:
        print('Ingest Report:\n')
        print(history_resp)
        break
    else:
        # wait for 20 seconds
        time.sleep(20)

    hour = timedelta(hours=1)
    date = datetime.datetime.utcnow() - hour
    history_range_resp = ingest_manager.get_history_range(date.isoformat() + 'Z')

    print('\nHistory scan report: \n')
    print(history_range_resp)