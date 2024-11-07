import os
import json
from time import sleep
import requests
from datetime import datetime

class Worker:
    def __init__(self):
        with open("config.json", "r") as config:
            config = json.loads(config.read())
        with open("rule_names", "r") as file:
            self.rule_list = [line.strip() for line in file]
        # Tenant ID
        self.tenant_ids = {}
        for tenant in config['tenant_ids']:
            self.tenant_ids[tenant['alias']] = tenant['tenant_id']
        # Cookie
        self.cookies = {}
        for tenant in config['tenant_ids']:
            self.cookies[tenant['alias']] = tenant['cookie']
        self.tenant_id, self.cookie = self.select_tenant()
        clear_screen()
        cookie_keys_to_extract = ['sccauth', 'XSRF-TOKEN', 'ai_session', 's.SessID', 'SSR']
        cookie_values = self.extract_values_from_cookie(self.cookie, cookie_keys_to_extract)
        self.sccauth = cookie_values['sccauth']
        self.xsrf_token = cookie_values['XSRF-TOKEN'].replace('%3A', ":")
        self.ai_session = cookie_values['ai_session']
        self.sess_id = cookie_values['s.SessID']
        self.ssr = cookie_values['SSR']
        self.start_time = datetime.now()
        
    def get_queries(self):
        uri = 'https://security.microsoft.com/apiproxy/mtp/huntingService/queries/?type=scheduled'
        headers, cookies = self.generate_header_data()
        response = requests.get(uri, headers = headers, cookies = cookies)
        if response:
            return json.loads(response.text)
        else:
            raise Exception("Unable to get rules from tenant, did the session time out?")

    def get_rule_info(self, query_id):
        uri = f'https://security.microsoft.com/apiproxy/mtp/huntingService/rules/byquery/{query_id}?tenantIds={self.tenant_id}'
        headers, cookies = self.generate_header_data()
        response = requests.get(uri, headers = headers, cookies = cookies)
        if response.status_code == 503:
            print("[-] status_code: 503 | reason: 'Service Unavailable'")
            print("[+] Waiting ...")
            sleep(30)
            print("[!] Retrying ...")
            return self.get_rule_info(query_id)
        response = json.loads(response.text)
        return response

    def create_id_list(self, queries):
        id_list = []
        for rule_name in self.rule_list:
            found = False
            for query in queries:
                if rule_name in query['Name']:
                    rule_info = self.get_rule_info(query['Id'])
                    id_list.append(rule_info['Id'])
                    found = True
                    break
            if not found:
                print("[-] Not Found: ", rule_name)
        return id_list

    def delete_rules(self, id_list):
        uri = 'https://security.microsoft.com/apiproxy/mtp/huntingService/rules'
        headers, cookies = self.generate_header_data()
        data = {"RuleIds": id_list}
        response = requests.delete(uri, json = data, headers = headers, cookies = cookies)
        if response.status_code == 200:
            print(response.text)
        else:
            print("[-] status_code:" + str(response.status_code))
            print("[!] Error at `delete_rules` function")
            exit()

    def get_query_text(self, query_id):
        uri = f'https://security.microsoft.com/apiproxy/mtp/huntingService/queries/{query_id}'
        headers, cookies = self.generate_header_data()
        response = requests.get(uri, headers = headers, cookies = cookies)
        if response.status_code == 503:
            print("[-] status_code: 503 | reason: 'Service Unavailable'")
            print("[+] Waiting ...")
            sleep(30)
            print("[!] Retrying ...")
            return self.get_query_text(query_id)
        response = json.loads(response.text)
        return response['QueryText']

    def select_tenant(self):
        # List the available aliases
        print("\nAvailable Tenants:\n")
        for i, alias in enumerate(self.tenant_ids.keys(), start=1):
            print(f"{i}. {alias}")

        # Select a tenant ID by alias
        while True:
            alias_input = input("\nEnter the number of the desired alias: ")
            try:
                alias_num = int(alias_input)
                if 1 <= alias_num <= len(self.tenant_ids):
                    selected_alias = list(self.tenant_ids.keys())[alias_num - 1]
                    selected_cookie = list(self.cookies.keys())[alias_num - 1]
                    return self.tenant_ids[selected_alias], self.cookies[selected_cookie]
                else:
                    print("Invalid input. Please try again.")
                    exit()
            except ValueError:
                print("Invalid input. Please try again.")
                exit()

    def generate_header_data(self):
        headers = {
            "authority": "security.microsoft.com",
            "method": "POST",
            "path": f"/apiproxy/mtp/huntingService/rules?tenantIds[]={self.tenant_id}",
            "scheme": "https",
            "accept": "application/json, text/plain, */*",
            "accept-encoding": "gzip, deflate, br, zstd",
            "accept-language": "tr-tr",
            "m-connection": "4g",
            "m-viewid": "",
            "origin": "https://security.microsoft.com",
            "priority": "u=1, i",
            "referer": "https://security.microsoft.com/v2/advanced-hunting?tid={self.tenant_id}",
            "sec-ch-ua": '"Not)A;Brand";v="99", "Google Chrome";v="127", "Chromium";v="127"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
            "tenant-id": self.tenant_id,
            "x-accepted-statuscode": "3..|4..|50.",
            "x-clientpage": "hunting-2@wicd-hunting",
            "x-tabvisible": "visible",
            "x-tid": self.tenant_id,
            "x-xsrf-token": self.xsrf_token
        }

        cookies = {
            "SSR": self.ssr,
            "at_check": "true",
            "BCP": "AD=1&AL=1&SM=1",
            "SRCHHPGUSR": "SRCHLANG=tr&DM=1&PV=15.0.0&CIBV=1.1418.9-suno",
            "i18next": "tr-TR",
            "s.SessID": self.sess_id,
            "s.Flight": "",
            "sccauth": self.sccauth,
            "X-PortalEndpoint-RouteKey": "neuprod_northeurope",
            "XSRF-TOKEN": self.xsrf_token,
            "ai_session": self.ai_session
        }

        return headers, cookies

    def extract_values_from_cookie(self, cookie, keys):
        # Split the cookie string into individual key-value pairs
        cookie_pairs = cookie.split('; ')
        # Convert to dictionary for easy access
        cookie_dict = {pair.split('=')[0]: pair.split('=')[1] for pair in cookie_pairs}
        # Extract the desired values
        extracted_values = {key: cookie_dict.get(key) for key in keys}
        return extracted_values


def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

if __name__ == '__main__':
    worker = Worker()
    clear_screen()
    queries = worker.get_queries()
    print(f"\x1b[1;31;43m[+] Fetched ({len(queries)}) queries\x1b[0;0m\n")
    id_list = worker.create_id_list(queries)
    worker.delete_rules(id_list)
    print(f"\x1b[1;31;43m[+] Deleted: ({len(id_list)}) rules\x1b[0;0m\n")
    end_time = datetime.now()
    print("\n\n\x1b[1;31;43m[!]Elapsed time: ", end_time - worker.start_time, "\x1b[0;0m\n")
