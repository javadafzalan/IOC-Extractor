import requests
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
def IOC_Extractor(ip_addresses):
    indicators=[]
    api_key=creds.api_key
    for ip_address in ip_addresses:
        print(f"\nGetting information for IP address: {ip_address}")
        result = get_virustotal_info(api_key, ip_address)
        json_result=json.dumps(result, indent=3)
        if result:           
            obj_analysis_stats=result["data"]["attributes"]["last_analysis_stats"]
            obj_analysis_results=result["data"]["attributes"]["last_analysis_results"]
            obj_security_vendors=obj_analysis_results.keys()
            for vendor in obj_security_vendors:
                if obj_analysis_results[vendor]["result"]=="malicious":
                    verdict="malicious"
                    break
                elif obj_analysis_results[vendor]["result"]=="malware":
                    verdict="malware"
                    break
                elif obj_analysis_results[vendor]["result"]=="suspicious":
                    verdict="suspicious"
                elif obj_analysis_results[vendor]["result"]=="clean":
                    verdict="clean"
                else:
                    verdict="unrated"
            obj_ip=result["data"]["id"]
            obj_type=result["data"]["type"]
            item_info={"ip" : obj_ip,
                       "type": obj_type, 
                       "provider": [
                           {"provider": "virustotal",
                            "verdict": verdict}
                     ]}
            indicators.append(item_info)
    return indicators
############################################################
ip_addresses = ['185.219.81.232',"192.168.1.1","8.8.8.8"]
print(json.dumps(IOC_Extractor(ip_addresses), indent=4))