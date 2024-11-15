from pathlib import Path
from pprint import pprint
from time import sleep
import hashlib
import argparse
import requests
import os, json
import pandas as pd

try:
    from key import API_KEY
except:
    API_KEY = "<Insert Api key>"

HEADERS = {"x-apikey": API_KEY}

def vt_get_data(md5hash):
    url = f"https://www.virustotal.com/api/v3/files/{md5hash}"
    while True:
        response = requests.get(url, headers=HEADERS)
        if error_handle(response):
            break
    return response

def error_handle(response):
    '''
    The function returns True if there are no errors
    and returns False otherwise

    :param response: requests.models.Response
    :return: bool
    '''
    if response.status_code == 429:
        print("WAITING")
        sleep(60)
    if response.status_code == 401:
        raise Exception("Invalid API key")
    elif response.status_code not in (200, 404, 429):
        raise Exception(response.status_code)
    else:
        return True
    
def parse_response(response):
    
    if response:
        last_analysis_stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {}) or ""
        threat_severity_level = response.json().get("data", {}).get("attributes", {}).get("threat_severity", {}).get("threat_severity_level", {}) or ""
        popular_threat_name = response.json().get("data", {}).get("attributes", {}).get("popular_threat_classification", {}).get("popular_threat_name", {}) or ""
        popular_threat_category = response.json().get("data", {}).get("attributes", {}).get("threat_severity", {}).get("threat_severity_data", {}).get("popular_threat_category", {}) or ""
        names = response.json().get("data", {}).get("attributes", {}).get("names", {}) or ""
        
        return json.dumps({
            "last_analysis_stats": last_analysis_stats,
            "threat_severity_level": threat_severity_level,
            "popular_threat_name": popular_threat_name,
            "popular_threat_category": popular_threat_category,
            "names": names
        }, indent = 4)
    
def main():
    
    parser = argparse.ArgumentParser(description="scan your files with virustotal")
    parser.add_argument("input_file", action="store", nargs=1, help="file containing hashes")
    parser.add_argument("column", action="store", nargs=1, help="column name containing hashes")
    parser.add_argument("result_column", action="store", nargs=1, help="VT Results")

    parsed_arg = parser.parse_args()
    input_file = Path(parsed_arg.input_file[0])
    column = parsed_arg.column[0]
    result_column = parsed_arg.result_column[0]

    if not input_file.exists():
        raise Exception(f"File not found: {input_file}")
    
    df = pd.read_excel(input_file)
    df[result_column] = None
    for index, row in df.iterrows():
        hash = row[column]
        response = vt_get_data(hash)

        vt_result = parse_response(response)
        df.loc[index, result_column] = vt_result
        # print(json.dumps(response.json(), indent=4))

    output_file = input_file.stem + "_vt_results.xlsx"
    df.to_excel(output_file, index=False)
    
if __name__ == "__main__":
    main()
    