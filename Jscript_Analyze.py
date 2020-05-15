import os
import sys
import re
import json
import subprocess
import urllib.parse
import requests
import jsbeautifier
from pathlib import Path
import requests.packages.urllib3
import random

import webbrowser

requests.packages.urllib3.disable_warnings()

Dom_Xss_Sinks = ['{"Sink_Name":"Execution Sink","Property_Susceptible":"eval"}',
                '{"Sink_Name":"Execution Sink","Property_Susceptible":"setTimeout"}',
                '{"Sink_Name":"Execution Sink","Property_Susceptible":"setInterval"}',
                '{"Sink_Name":"HTML Element Sink","Property_Susceptible":"document.write"}',
                '{"Sink_Name":"HTML Element Sink","Property_Susceptible":"document.writeIn"}',
                '{"Sink_Name":"HTML Element Sink","Property_Susceptible":"innerHTML"}',
                '{"Sink_Name":"HTML Element Sink","Property_Susceptible":"outerHTML"}',
                '{"Sink_Name":"Set Location Sink","Property_Susceptible":"location"}',
                '{"Sink_Name":"Set Location Sink","Property_Susceptible":"location.href"}']


DOWNLOADER_MIDDLEWARES = {
    'scrapy.downloadermiddlewares.useragent.UserAgentMiddleware': None,
    'scrapy_useragents.downloadermiddlewares.useragents.UserAgentsMiddleware': 500,
}

USER_AGENTS = [
    ('Mozilla/5.0 (X11; Linux x86_64) '
     'AppleWebKit/537.36 (KHTML, like Gecko) '
     'Chrome/57.0.2987.110 '
     'Safari/537.36'),  # chrome
    ('Mozilla/5.0 (X11; Linux x86_64) '
     'AppleWebKit/537.36 (KHTML, like Gecko) '
     'Chrome/61.0.3163.79 '
     'Safari/537.36'),  # chrome
    ('Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:55.0) '
     'Gecko/20100101 '
     'Firefox/55.0'),  # firefox
    ('Mozilla/5.0 (X11; Linux x86_64) '
     'AppleWebKit/537.36 (KHTML, like Gecko) '
     'Chrome/61.0.3163.91 '
     'Safari/537.36'),  # chrome
    ('Mozilla/5.0 (X11; Linux x86_64) '
     'AppleWebKit/537.36 (KHTML, like Gecko) '
     'Chrome/62.0.3202.89 '
     'Safari/537.36'),  # chrome
    ('Mozilla/5.0 (X11; Linux x86_64) '
     'AppleWebKit/537.36 (KHTML, like Gecko) '
     'Chrome/63.0.3239.108 '
     'Safari/537.36'),  # chrome
]

def download_javascript(url):
    disassembled = urllib.parse.urlparse(url)
    filename_js, file_ext = os.path.splitext(os.path.basename(disassembled.path))
    jscript_path =  'jsfiles/' + filename_js + file_ext
    print(jscript_path)
    try:
        user_agent = random.choice(USER_AGENTS)
        headers = {'User-Agent': user_agent}
        r = requests.get(url, verify=False, timeout=3, allow_redirects=False)

        if r.text:
           return r.text, jscript_path
          
    except Exception as ErrMsg:
        print(ErrMsg)
        pass

def javascript_grabber(paths):
    #https://github.com/003random/getJS
    # grab javascript from responding remote url
    print("grabbing javascript from Url:" + paths)
    cmd = ('getJS -resolve  -complete -url ' + paths)
    mycmd_result = subprocess.getoutput(cmd)
    if mycmd_result:
       return mycmd_result
    else:
       pass

        
def function_time(regex_str,jscript_file):
    #grab 5 lines after and before to try to get better visibility to the code affected 
    cmd =  "grep -n -C 5 "+regex_str+"  "+ jscript_file

    sp = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output = ""
    while True:
        out = sp.stdout.read(1).decode('utf-8')
        if out == '' and sp.poll() != None:
            break
        if out != '':
           output += out
           sys.stdout.write(out)
           sys.stdout.flush()

    if output:
       #transform data into linted json
       xss_hit = {}
       xss_hit['file_name'] = str(jscript_file)
       xss_hit['Sink_found'] = str(output)
       xss_hit["Property_Susceptible"] = regex_str
       print(json.dumps(xss_hit))
       return json.dumps(xss_hit)
           
   
       


def dom_xss_search(jscript_file):
    flagged_code_hits = []
    for items in Dom_Xss_Sinks:
        tmp_item = json.loads(items)
        for key in tmp_item:
            if "Property_Susceptible" in key:
                print("trying to test sink: "+tmp_item["Property_Susceptible"])
                try:
                    result = function_time(tmp_item["Property_Susceptible"],jscript_file)
                    if result:
                       #print(result)
                       flagged_code_hits.append(json.dumps(result))
                except Exception as ex:
                    print(ex)
                  
    return flagged_code_hits


def main():
    try:
       js_paths = []                 
       results = javascript_grabber(sys.argv[1])#enter target it will give you urls of javascripts download put in dir
       clean = list(results.split())
       print(len(clean))
       for url in clean:
           print("Grabbing Javascript From URL "+str(url))
           file_content,file_desired_path = download_javascript(url)
           print("Desired Path "+file_desired_path)
           beautiful_js = jsbeautifier.beautify(file_content)
           if Path(file_desired_path).is_file():
              print ("File exists Will Be Tested During Dom Testing")
              js_paths.append(file_desired_path)
           else:
              print ("File does not exist Creating and writing Content")
              outfile = open(file_desired_path,'w')
              outfile.write(beautiful_js)
              outfile.close()
              js_paths.append(file_desired_path)
              #now we try to create these files if they don't exist and evaluate if there are sinks
       try:
           for js_tests in js_paths:
               print("Testing " +js_tests)
               json_out = open("json_out.json","a")
               sink_results = dom_xss_search(js_tests)  #this is used to extract the sinks this is called per file 
               for sink in sink_results:
                   json_out.write(json.dumps(sink)+"\n")
               json_out.close()
          
       except Exception as ohnoz:
             print(ohnoz)

    except Exception as wellnow:
       print(wellnow)

main()
