import json
import subprocess as sp
import os
import sys

def split_pcap(capture_path: str) :
    path = './' + capture_path
    capture_path = capture_path + '.pcap'
    # Check whether the specified path exists or not
    isExist = os.path.exists(path)

    if not isExist:
  
        # Create a new directory because it does not exist 
        os.makedirs(path)
        print("The new directory was created!")

    #"./splitpcap/splitpcaps"
    cmds = ["tcpdump", "-r",  capture_path, "-w", path + "/splitpcaps", "-C", "1"]
    sp.run(cmds)

    for filename in os.listdir(path):
        infilename = os.path.join(path,filename)
        if not os.path.isfile(infilename): continue
        output = os.rename(infilename, infilename + '.pcap')


def get_tshark_hexstreams(datafile: str) :
    path = './' + datafile
    datafile = datafile + '.csv'

    with open(datafile, "a+") as outfile:
        
        files = os.listdir(path)
        files.sort(key=lambda x: os.path.getmtime(os.path.join(path,x)))
        for filename in files :
            
            if filename.endswith(".json"):
                infilename = os.path.join(path,filename)
                if not os.path.isfile(infilename): continue
                print(infilename)
                # Opening JSON file
                with open(infilename, 'rb') as openfile:
    
                # Reading from json file
                    frames_json = json.load(openfile)
                    for frame in frames_json :
                        outfile.write(frame["_source"]["layers"]["frame"]["frame.time_epoch"][:-3] + ', ' + frame["_source"]["layers"]["frame_raw"][0] + '\n')
                        


def convert_to_json(datafile: str) :
    path = './' + datafile
    
    files = os.listdir(path)
    files.sort(key=lambda x: os.path.getmtime(os.path.join(path,x)))
    for filename in files :
        
        if filename.endswith(".pcap"):
            infilename = os.path.join(path,filename)
            if not os.path.isfile(infilename): continue
            newname = infilename.replace('.pcap', '.json')

            f = open(newname, "w")
            sp.call(["tshark", "-x", "-r", infilename, "-T", "json"], stdout=f)
    

if len(str(sys.argv[1])) > 3 :
    name = str(sys.argv[1])
    split_pcap(name)
    convert_to_json(name)
    get_tshark_hexstreams(name)

