import os
import glob
import ember
import lightgbm as lgb
from pprint import pprint
from virustotal_python import Virustotal
import requests
from stix2 import Malware
import json
import hashlib
import string
import random
import urllib3
from elasticsearch import Elasticsearch
from datetime import datetime

print('Starting. Please Wait......')

lgbm_model = lgb.Booster(model_file="H:\\jupyter\\ember\\ember_model_2018.txt") # Trained model location
vtotal = Virustotal(API_VERSION="v3") # ADD API Key to your environment variables
base = "https://cve.circl.lu/api/cve/"
previous_op=''
link=urllib3.PoolManager()

elastic_client = Elasticsearch(['localhost'],
    http_auth=('username', 'password'))

def get_random_string(length):
    letters = string.ascii_lowercase
    result_str = ''.join(random.choice(letters) for i in range(length))
    return result_str

def query_this(quer):
    res = elastic_client.search(index='event*', body={
    "query": {
    "bool": {
      "filter": [
        {
          "match_all": {}
        },
        {
          "match_phrase": {
            "name.keyword": quer
          }
        }
      ]
    }}}, size=1 )
    return res['hits']['hits']
try:
    while True:
        try:
            list_of_files = glob.glob('C:\\Users\\rahul\\Downloads\\*')
            latest_file = max(list_of_files, key=os.path.getctime)
            if previous_op != latest_file:
                print(latest_file)
                check_file=open(latest_file, "rb").read()
                results=(ember.predict_sample(lgbm_model, check_file))*100
                print(results)
                ai_res={}
                ai_res["ai_prediction"]=results
                FILE_ID = hashlib.md5(check_file).hexdigest()
                if results >=51:
                    ai_res["ai_decision"]='True Positive'
                    qu=query_this('Malware '+FILE_ID)
                else:
                    ai_res["ai_decision"]='False Positive'
                    qu=query_this('Not a Malware '+FILE_ID)
                if len(qu)==0:
                    try:
                        resp = vtotal.request(f"files/{FILE_ID}")
                        pprint(resp.data)
                    except Exception as e1:
                        resp={}
                        resp["Intelligence status"]=False
                        print("No Intelligence found")
                    if resp["Intelligence status"] != False:
                        for y,z in enumerate(resp.data['attributes']['tags']):
                            if z[0:3] == 'cve':
                                url = base + z[y]
                                cve_response = requests.get(url)
                                if cve_response != None:
                                    print(cve_response.json())
                                    cve=json.dumps(cve_response.json())
                                    cve=cve[:-1]+',"cve_response":True}'
                                else:
                                    print("No CVE Data found")
                                    cve_response={"cve_response":False}
                                    cve=json.dumps(cve_response)
                            else:
                                print("No CVE Data found")
                                cve_response={"cve_response":False}
                                cve=json.dumps(cve_response)
                        malware = Malware(name='Malware '+resp.data['attributes']['md5'],
                        is_family=False)
                        res=json.dumps(resp.data)
                        res=res[:-1]+',"Intelligence status":True}'
                    else:
                        malware = Malware(name='Not a Malware '+FILE_ID,
                        is_family=False)
                        res=json.dumps(resp)
                        print("No CVE Data found")
                        cve_response={"cve_response":False}
                        cve=json.dumps(cve_response)
                    ds={}
                    for i in malware:
                        ds[i]=str(malware[i])
                    ds=json.dumps(ds)
                    ai_res=json.dumps(ai_res)
                    op='{"timestamp":"'+ str(datetime.now()) +'",'+ai_res[1:-1]+','+ds[1:-1]+','+res[1:-1]+','+cve[1:]
                    print(op)
                    send=elastic_client.index(index='event_profile',id=get_random_string(20),body=json.loads(op))
                    print(send)
                else:
                    pprint(qu[0]['_source'])
                previous_op=latest_file
        except OSError as e:
            pass
except:
    print("Exiting the program...")
