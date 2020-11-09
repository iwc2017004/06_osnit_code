import json



class Wrap:
    def ExtractAndMerge(self):
        handle = open("/home/ubuntu/Desktop/06_Nov_2020_OSINT/output/intel_owl_reports.json","r")
        content = handle.read()

        data = json.loads(content)
        print("type data ==",type(data))
        number = len(data)

        needed_data = {}

        needed_data["md5==="]={}
        for n in range(number):
            #print(data[n])
            try:
                if(data[n].get("name", None) == "VirusTotal_v2_Get_Observable"):
                    needed_data["VirusTotal_v2_Get_Observable"] = {"Errors" : data[n].get("errors", None), 
                                                                    "Total":data[n]["report"].get("total", None),
                                                                    "Positives" : data[n]["report"].get("positives", None),
                                                                    "URL":data[n]["report"].get("permalink", None)}
                    
                    # needed_data1["VirusTotal_v2_Get_Observable"] = {"Errors" : data[n].get("errors", None), "Total":data[n]["report"].get("total", None),"Positives" : data[n]["report"].get("positives", None),"URL":data[n]["report"].get("permalink", None)}
                    # print("<------------------------------", data[n]["name"],"---------------------------------------------->")
                    # print("Errors                  :",data[n].get("errors", None))
                    # print("Total                   :", data[n]["report"].get("total", None))
                    # print("Positives               :", data[n]["report"].get("positives", None))
                    # print("URL                     :",data[n]["report"].get("permalink", None))

                if (data[n].get("name", None) == "MalwareBazaar_Get_Observable"):
                    needed_data["MalwareBazaar_Get_Observable"] = {"Errors": data[n].get("errors", None),"Report" : data[n].get("report", None),"Success" : data[n].get("success", None)}

                    # print("<------------------------------", data[n]["name"], "---------------------------------------------->")
                    # print("Errors                   :", data[n].get("errors", None))
                    # print("Report                   :", data[n].get("report", None))
                    # print("Success                  :", data[n].get("success", None))

                if (data[n].get("name", None) == "MISPFIRST"):
                    needed_data["MISPFIRST"] ={"Errors" : data[n].get("errors", None), "Report" : data[n].get("report", None), "Success" : data[n].get("success", None) }

                    # print("<------------------------------", data[n]["name"], "---------------------------------------------->")
                    # print("Errors                    :", data[n].get("errors", None))
                    # print("Report                    :", data[n].get("report", None))
                    # print("Success                   :", data[n].get("success", None))

                if (data[n].get("name", None) == "OTXQuery"):
                    needed_data["OTXQuery"] ={"Errors": data[n].get("errors", None),"Report": data[n].get("report", None),"Success ": data[n].get("success", None),"url_list" :data[n]["report"].get("url_list", None) }

                    # print("<------------------------------", data[n]["name"], "---------------------------------------------->")
                    # print("Errors                    :", data[n].get("errors", None))
                    # # print("Report                    :", data[n].get("report", None))
                    # print("Success                   :", data[n].get("success", None))
                    # print("url_list                  :", data[n]["report"].get("url_list", None))

                if (data[n].get("name", None) == "MISP"):
                    needed_data["MISP"] ={"Errors" : data[n].get("errors", None),"Report" : data[n].get("report", None),"Success" : data[n].get("success", None)}


                    # print("<------------------------------", data[n]["name"], "---------------------------------------------->")
                    # print("Errors                   :", data[n].get("errors", None))
                    # print("Report                   :", data[n].get("report", None))
                    # print("Success                  :", data[n].get("success", None))

                if (data[n].get("name", None) == "Cymru_Hash_Registry_Get_Observable"):
                    needed_data["Cymru_Hash_Registry_Get_Observable"] ={"Errors" : data[n].get("errors", None), "Report_Found": data[n]["report"].get("found", None), "Report_resolution_data" : data[n]["report"].get("resolution_data", None),"Success" : data[n]["success"]}
            
                    # print("<------------------------------", data[n]["name"], "---------------------------------------------->")
                    # print("Errors                     :", data[n].get("errors", None))
                    # print("Report_Found               :", data[n]["report"].get("found", None))
                    # print("Report_resolution_data     :", data[n]["report"].get("resolution_data", None))
                    # print("Success                    :", data[n]["success"])

                if (data[n].get("name", None) == "HybridAnalysis_Get_Observable"):
                    needed_data["HybridAnalysis_Get_Observable"] ={"Errors": data[n]["errors"],"Report": data[n]["report"],"verdict": data[n]["report"][0].get("verdict", None),"av_detect": data[n]["report"][0].get("av_detect", None),"target_url":data[n]["report"][0].get("target_url", None),"threat_level" :data[n]["report"][0].get("threat_level", None),"threat_score " : data[n]["report"][0].get("threat_score", None),"total_signatures " : data[n]["report"][0].get("total_signatures", None),"Success": data[n]["success"]}
                    
                    
                    # print("<------------------------------", data[n]["name"], "---------------------------------------------->")
                    # try:
                    #     print("Errors                      :", data[n]["errors"])
                    #     print(json.dumps(data[n]["report"], indent=4, sort_keys=True))
                    #     # print("Report                      :", data[n]["report"], indent=4)                                               
                    #     print("verdict                     :", data[n]["report"][0].get("verdict", None))
                    #     print("av_detect                   :", data[n]["report"][0].get("av_detect", None))
                    #     print("target_url                  :", data[n]["report"][0].get("target_url", None))
                    #     print("threat_level                :", data[n]["report"][0].get("threat_level", None))
                    #     print("threat_score                :", data[n]["report"][0].get("threat_score", None))
                    #     print("total_signatures            :", data[n]["report"][0].get("total_signatures", None))
                    # except KeyError:
                    #     pass 
                    # except IndexError:
                    #     pass 

                    # print("Success                    :", data[n]["success"])
                
                if (data[n].get("name", None)  == "VirusTotal_v3_Get_Observable"):
                    needed_data["VirusTotal_v3_Get_Observable"] ={"Errors":data[n].get("errors", None),"type" : data[n]["report"]["data"].get("type", None),"links": data[n]["report"]["data"]["links"].get("self", None),"import_list": data[n]["report"]["data"]["attributes"]["pe_info"].get("import_list", None),"malicious" : data[n]["report"]["data"]["attributes"]["last_analysis_stats"].get("malicious", None),"signatures" : data[n]["report"]["data"]["attributes"]["last_analysis_results"]["AVG"].get("result", None)}


                    # print("<------------------------------", data[n]["name"], "---------------------------------------------->")
                    # print("Errors                  :", data[n].get("errors", None))
                    # print("type                    :", data[n]["report"]["data"].get("type", None))
                    # print("links                   :", data[n]["report"]["data"]["links"].get("self", None))
                    # try:
                    #     print("import_list             :", data[n]["report"]["data"]["attributes"]["pe_info"].get("import_list", None))           
                    # except KeyError:
                    #     pass
                        
                    # print("malicious               :", data[n]["report"]["data"]["attributes"]["last_analysis_stats"].get("malicious", None))
                    # print("signatures              :", data[n]["report"]["data"]["attributes"]["last_analysis_results"]["AVG"].get("result", None))

                
                
            except KeyError:
                pass   
        f2 = open("/home/ubuntu/Desktop/06_Nov_2020_OSINT/output/sandbox_api_reports.json","r")
        data2 = json.loads(f2.read())
        f2.close()
                
        needed_data.update(data2)
        #print(needed_data)
        with open("/home/ubuntu/Desktop/06_Nov_2020_OSINT/output/parse_output.json", "w") as outfile:
            json.dump(needed_data,outfile, indent=4)  


            
if __name__ == "__main__":
    myobj = Wrap()

    try:
        myobj.ExtractAndMerge()
                        
    except Exception as e:
            print(e)
