import requests, json,time
splunk_address = "127.0.0.1" # YOUR SPLUNK IP OR HOSTNAME
nessusScan_URL = "https://10.10.10.100:8834/scans/" # YOUR NESSUS SCAN URL
#nessusScan_Hosts = nessusScan_URL + "/hosts/"
nessus_Auth = {'X-ApiKeys': "accessKey=<accessKey>; secretKey=<secretKey>"}
def main():
  getNessusScan()
def getNessusScan():
  for i in range(1,20,1):
    nessusScan_URLD=nessusScan_URL+str(i)
    response_Nessus = requests.request("GET", nessusScan_URLD, headers=nessus_Auth, verify=False)
    if response_Nessus.status_code == 200:
      print i
      parseJSON = json.loads(response_Nessus.text)
      for machine in parseJSON['hosts']:
        nessusScan_Hosts=nessusScan_URLD+"/hosts/"
        url_hostid = nessusScan_Hosts + str(machine['host_id'])
        hostname = {'hostname': str(machine['hostname'])}
        response_host = requests.request("GET", url_hostid, headers=nessus_Auth, verify=False)
        parseJSON_Host = json.loads(response_host.text)
        for vulnerability in parseJSON_Host['vulnerabilities']:
          vulnerability.update(hostname)
          count=vulnerability['count']
          host=vulnerability['hostname']
          plugin_name=vulnerability['plugin_name']
          log=str(count)+"|"+str(host)+"|"+str(plugin_name)+"\n"
          dosya=open("/tmp/nessusKale.txt","w")
          dosya.write(log)
          dosya.close()
          sendSplunk()
          time.sleep(1)
          print "Gonderildi"
    else:
      print("The server seems not working.")
def sendSplunk():
  import splunklib.client as client
  import splunklib.results as results
  from splunklib.binding import AuthenticationError
  HOST="127.0.0.1"
  PORT = '8089'
  USERNAME = 'splunk'
  PASSWORD = '1qaz2wsx'
  try:
    service = client.connect(host=HOST, port=PORT, username=USERNAME, password=PASSWORD)
  except exception as e:
    print(str(e))
    myindex = service.indexes['main'] # Retrieve the index for the data
  try:
    myindex.upload('/tmp/nessusKale.txt') # Upload file
  except Exception as e:
    print(str(e))
if __name__ == "__main__":
  main()
