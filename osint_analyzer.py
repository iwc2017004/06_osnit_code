from cuckoo_analysis import (post_file_for_cuckoo_analysis,get_report_for_task_id)
from get_reports import Malware
from osintscan import Osint
import os
import json
import hashlib
from pyintelowl_client import get_reports_from_intelowl_server
import io

class OSINT_Analyzer:
    def __init__(self,file_path,output_path,api_token_file,intelowl_url):
        self.file_path = file_path
        self.file_hash = self.hash_gen(self.file_path)
        self.output_path = output_path
        #self.malware_reports = Malware(file=self.file_path)
        self.osint_reports = Osint(hash=self.file_hash,file=self.file_path)
        self.api_token_file = api_token_file
        self.intelowl_url = intelowl_url
        self.pyintelowl_result = None
        self.osint_reports_analysis_result = None

    def nmr_osint_get_report_from_cuckoo(self):
        self.cuckoo_report = post_file_for_cuckoo_analysis(self.file_path)

    def nmr_osint_save_cuckoo_results_to_json(self):
        with open(os.path.join(self.output_path,'cuckoo_analysis.json'),'w') as file:
            json.dump(self.cuckoo_report,file)

    def nmr_osint_get_malware_api_reports(self):
        self.malware_reports_analysis_result = self.malware_reports.main()
        self.malware_reports.driver.quit()
        print('Info: Collecting reports successful')

    def nmr_osint_save_malware_api_reports_to_json(self):
        with open(os.path.join(self.output_path,'osint_api_reports.json'),'w') as file:
            json.dump(self.malware_reports_analysis_result,file)

    def nmr_osint_get_malware_sandbox_reports(self):
        self.osint_reports_analysis_result = self.osint_reports.main()
        print('Info: Collecting reports successful')

    def nmr_osint_save_malware_sandbox_reports(self):
        with open(os.path.join(self.output_path,'sandbox_api_reports.json'),'w') as file:
            json.dump(self.osint_reports_analysis_result,file, indent=4)


    def nmr_osint_save_malware_api_reports_to_json(self):
        with open(os.path.join(self.output_path,'osint_api_reports.json'),'w') as file:
            json.dump(self.malware_reports_analysis_result,file)

    def nmr_osint_get_pyintelowl_report(self):
        self.pyintelowl_result = get_reports_from_intelowl_server(self.file_path,self.api_token_file,self.intelowl_url)

    def nmr_osint_save_pyintelowl_report_to_json(self):
        with open(os.path.join(self.output_path, 'intel_owl_reports.json'), 'w') as file:
            json.dump(self.pyintelowl_result, file, indent=4)



    def hash_gen(self,file_path):
        """Generate and return sha1 and sha256 as a tuple."""
        try:
            print('Generating Hashes')
            md5 = hashlib.md5()
            block_size = 65536
            with io.open(file_path, mode='rb') as afile:
                buf = afile.read(block_size)
                while buf:
                    md5.update(buf)
                    buf = afile.read(block_size)
            md5 = md5.hexdigest()
            return md5
        except Exception as ex:
            print('Error:Generating Hashes',ex)
    def ForStatus(self,pos):
        if(success>0):
            temp = "Found"
        elif(success == 0):
            temp ="Notfound"
        else:
            temp = "Error"


    def ExtractAndMerge(self):
        #handle = open("/home/ubuntu/Desktop/06_Nov_2020_OSINT/output/intel_owl_reports.json","r")
        #content = handle.read()

        data = self.pyintelowl_result #json.loads(content)update
        number = len(data)
        
        needed_data = {}

        needed_data["md5==="]={}
        for n in range(number):
            #print(data[n])
            # try:
            if(data[n].get("name", None) == "VirusTotal_v2_Get_Observable"):
                needed_data["VirusTotal_v2"] = {"Status" : data[n].get("success", 0),
                                                "Positives" : data[n]["report"].get("positives", 0), 
                                                    "Total":data[n]["report"].get("total", None),
                                                    "URL":data[n]["report"].get("permalink", None),
                                                    # "Signatures":"Malicious" if (data[n]["positives" > 0) else "Clean" ,    
                                                    "Errors" : data[n].get("errors", None)
                                                    }                                                                                  
                                                                                                       
                    
                    
            if (data[n].get("name", None) == "MalwareBazaar_Get_Observable"):
                needed_data["MalwareBazaar"] = {"Status" : data[n].get("success", None),
                                                    "Positives" : data[n]["report"].get("positives", None), 
                                                    "Total":data[n]["report"].get("total", None),
                                                    "URL":data[n]["report"].get("permalink", None),
                                                    # "Signatures":"Malicious" if (data[n]["positives" > 0) else "Clean" ,    
                                                    "Errors" : data[n].get("errors", None)}                   
               

                   
            if (data[n].get("name", None) == "MISPFIRST"):
                needed_data["MISPFIRST"] ={ "Status" : data[n].get("success", None),
                                                "Positives" : data[n]["report"].get("positives", 0), 
                                                "Total":data[n]["report"].get("total", 0),
                                                "URL":data[n]["report"].get("permalink", "NULL"),
                                                # "Signatures":"Malicious" if (data[n]["positives" > 0) else "Clean" ,    
                                                "Errors" : data[n].get("errors", None) }


            if (data[n].get("name", None) == "OTXQuery"):
                needed_data["OTXQuery"] ={"Status" : data[n].get("success", None),
                                                "Positives" : data[n]["report"].get("positives", 0), 
                                                "Total":data[n]["report"].get("total", 0),
                                                "URL":data[n]["report"].get("url_list", "NULL"),
                                                # "Signatures":"Malicious" if (data[n]["positives" > 0) else "Clean" ,    
                                                "Errors" : data[n].get("errors", None) }                
                        


            if (data[n].get("name", None) == "MISP"):
                needed_data["MISP"] ={"Status" : data[n].get("success", None),
                                            "Positives" : data[n]["report"].get("positives", 0), 
                                            "Total":data[n]["report"].get("total", 0),
                                            "URL":data[n]["report"].get("url", "NULL"),
                                            # "Signatures":"Malicious" if (data[n]["positives" > 0) else "Clean" ,    
                                            "Errors" : data[n].get("errors", None) }  
                        
                        
                                   

            if (data[n].get("name", None) == "Cymru_Hash_Registry_Get_Observable"):
                needed_data["Cymru_Hash_Registry"] ={"Status" : data[n]["report"].get("found", None),
                                                        "Positives" : data[n]["report"].get("positives", 0), 
                                                        "Total":data[n]["report"].get("total", 0),
                                                        "URL":data[n]["report"].get("url", "NULL"),
                                                        # "Signatures":"Malicious" if (data[n]["positives" > 0) else "Clean" ,    
                                                        "Errors" : data[n].get("errors", None) }  
                   
                    

            if (data[n].get("name", None) == "HybridAnalysis_Get_Observable"):
                needed_data["HybridAnalysis"] ={"Status" : data[n]["report"][0].get("verdict", None),
                                                        "Positives" :data[n]["report"][0].get("av_detect", None), 
                                                        "Total":data[n]["report"][0].get("total", "Not Given"),
                                                        "URL":data[n]["report"][0].get("target_url", None),
                                                        "Signatures":data[n]["report"][0].get("vx_family", None) ,    
                                                        "Errors" : data[n].get("errors", None),
                                                        "total_signatures " : data[n]["report"][0].get("total_signatures", None)}
                    
                    
                
            if (data[n].get("name", None)  == "VirusTotal_v3_Get_Observable"):
                pos = data[n]["report"]["data"]["attributes"]["last_analysis_stats"].get("malicious", 0)
                if(success>0):
                    temp = "Found"
                elif(success == 0):
                    temp ="Notfound"
                else:
                    temp = "Error"
                
                needed_data["VirusTotal_v3"] ={"Engine": data[n].get("name", None),
                                               "Status" : temp
                                               "Positives" :data[n]["report"]["data"]["attributes"]["last_analysis_stats"].get("malicious", None),
                                               "Total":data[n]["report"].get("total","Not_Given"),
                                               "URL":data[n]["report"]["data"]["links"].get("self", None),
                                               "Signatures":data[n]["report"]["data"]["attributes"]["last_analysis_results"]["AVG"].get("result", None),
                                               "Errors" : data[n].get("errors", None),
                                               
                }
                # 
                #                                          "Status" : data[n]["report"][0].get("verdict", None),  #if positive
                #                                          "malicious" : data[n]["report"]["data"]["attributes"]["last_analysis_stats"].get("malicious", None)
                #                                         
                #                                         
                #                                          ,    
                #                                         
                #                                                               
                                         

                
                
           
            # except KeyError:
            #     pass
            # except IndexError:
            #     pass 
        data2 = self.osint_reports_analysis_result    
        
        needed_data.update(data2)
        with open("/home/ubuntu/Desktop/06_Nov_2020_OSINT/output/parse_output2.json", "w") as outfile:
            json.dump(needed_data,outfile, indent=4)  





    def run(self):
        #self.nmr_osint_get_report_from_cuckoo()
        #self.nmr_osint_save_cuckoo_results_to_json()
        # self.nmr_osint_get_malware_api_reports()
        # self.nmr_osint_save_malware_api_reports_to_json()

        self.nmr_osint_get_malware_sandbox_reports()
        self.nmr_osint_save_malware_sandbox_reports()
        self.nmr_osint_get_pyintelowl_report()
        self.nmr_osint_save_pyintelowl_report_to_json()
        self.ExtractAndMerge()

if __name__=='__main__':
    osint_analyzer = OSINT_Analyzer(r'/home/ubuntu/Desktop/samples/Git.exe',r'output',r'api_token.txt','http://10.10.106.101')
    osint_analyzer.run()
    

