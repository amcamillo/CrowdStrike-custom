# usage: create a .env file on the same directory with your own API creds:
# CLIENT_ID = xxx
# CLIENT_SECRET = xxx

import os
from falconpy import SensorDownload
from dotenv import load_dotenv

load_dotenv()

# Do not hardcode API credentials!
falcon = SensorDownload(client_id=os.getenv('CLIENT_ID'),
                        client_secret=os.getenv('CLIENT_SECRET')
                        )

response = falcon.get_combined_sensor_installers_by_query(offset=0,
                                                          limit=1,
                                                          sort="release_date.desc",
                                                          filter="platform:'windows'"
                                                          )
print(response)
