import requests
#api_key variables are defined in "creds.py file" which should be created and used by yourself
import creds
import json
def get_virustotal_info(api_key, ip_address):
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}'
    headers = {
        'x-apikey': api_key,
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error: {response.status_code}")
        return None
def get_abuse_ipdb_info(api_key, ip_address):
    url = 'https://api.abuseipdb.com/api/v2/check'
    querystring = {
        'ipAddress': ip_address,
        'maxAgeInDays': '90'
    }

    headers = {
        'Accept': 'application/json',
        'Key': api_key
    }
    response = requests.request(method='GET', url=url, headers=headers, params=querystring)
    if response.status_code==200:
        decodedResponse = json.loads(response.text)
        return decodedResponse
    else:
        print(f"Error: {response.status_code}")
        return None
def IOC_Extractor(ip_addresses):
    indicators=[]
    virustotal_api_key=creds.virustotal_api_key
    abuseipdb_api_key=creds.abuseipdb_api_key
    for ip_address in ip_addresses:
        print(f"\nGetting information for IP address: {ip_address}")
        ##########ABUSE_IP_DB##############
        abuseipdb_result=get_abuse_ipdb_info(abuseipdb_api_key,ip_address)
        if abuseipdb_result["data"]["abuseConfidenceScore"] >  20:
            abuseipdb_verdict="malicious"
        else:
            abuseipdb_verdict="clean"
        ##########VIRUSTOTAL##############
        virustotal_result = get_virustotal_info(virustotal_api_key, ip_address)
        if virustotal_result:
            virustotal_obj_analysis_results=virustotal_result["data"]["attributes"]["last_analysis_results"]
            virustotal_obj_security_vendors=virustotal_obj_analysis_results.keys()
            for vendor in virustotal_obj_security_vendors:
                if virustotal_obj_analysis_results[vendor]["result"]=="malicious":
                    verdict="malicious"
                    break
                elif virustotal_obj_analysis_results[vendor]["result"]=="malware":
                    verdict="malware"
                    break
                elif virustotal_obj_analysis_results[vendor]["result"]=="suspicious":
                    verdict="suspicious"
                elif virustotal_obj_analysis_results[vendor]["result"]=="clean":
                    verdict="clean"
                else:
                    verdict="unrated"
            obj_ip=virustotal_result["data"]["id"]
            obj_type=virustotal_result["data"]["type"]
            
            item_info={"ip" : obj_ip,
                       "type": obj_type, 
                       "provider": [
                           {"provider": "virustotal",
                            "verdict": verdict},
                            {"provider": "abuse_ipdb",
                            "verdict": abuseipdb_verdict}
                     ]}        
            indicators.append(item_info)
    return indicators
############################################################
ip_addresses = ["185.219.81.232","43.156.118.145","195.158.24.42"]
print(json.dumps(IOC_Extractor(ip_addresses), indent=4))
