
import json
# data1 = data2 = ""
      
f1 = open("/home/ubuntu/Desktop/06_Nov_2020_OSINT/output/parse_output.json","r")
data = json.loads(f1.read())
print(type(data))
f1.close()


f2 = open("/home/ubuntu/Desktop/06_Nov_2020_OSINT/output/sandbox_api_reports.json","r")
data.append(json.loads(f2.read()))
print(type(data))
f2.close()



#print(type(data1))
with open("/home/ubuntu/Desktop/06_Nov_2020_OSINT/output/merged_file.json","w") as f3:
    json.dump(data, f3, indent=4)

