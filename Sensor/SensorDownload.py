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

#sha256_value = response.get('sha256')
sha256_value = response['body']['resources'][0]['sha256']
#debugging: print("sha265 = ", sha256_value)

downloads = falcon.download_sensor_installer(id= sha256_value,
                                            #download_path="/tmp/",
                                             download_path=os.path.join(os.path.expanduser('~'), 'Downloads'),
                                            file_name="cs_installer.exe"
                                            )
print(downloads)
