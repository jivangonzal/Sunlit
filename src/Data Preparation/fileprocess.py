import json
import subprocess as sp
import os
import dask.dataframe as dd
import numpy as np
import pandas as pd
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
                        

def join_with_labeled_data(datafile: str) :
    path = './' + datafile
    
    df = dd.read_csv(
      datafile + '.labeled',
      sep = '\s+',
      header=None,
      dtype=str
    )

    df2 = dd.read_csv(
      datafile + '.csv',
      sep = ',',
      header=None,
      dtype=str
    )

    df1 = df.iloc[:, [0, 21]]

    # Merge the csv files.
    df3 = dd.merge(df2, df1, how='inner', on = 0)

    # Write the output.
    df3.to_csv(path + '/' + path + '.merged', single_file = True, index=False, header=False)


def sliceNgram(capture_path: str) :
    path = './' + capture_path
    output_path = capture_path + '.final.csv'

    df = pd.read_csv(
        path + '.merged',
        sep = ',',
        header=None,
        dtype=str
    )

    df[2] = df[2].str.replace('Benign','0')
    df[2] = df[2].str.replace('Malicious','1')
    df = df.iloc[:,[1,2]]

    b = np.linspace(0,187,188, dtype=int)
    c = np.linspace(5,192,188, dtype=int)
    d = zip(b,c)

    with open(output_path, "a+") as outfile:
        for y in range(len(df)):
              a = df.iloc[y,0].ljust(192, '0').strip()
              z = map(lambda x: a[slice(*x)], zip(b,c))
              outfile.write(" ".join(z) + ', ' + df.iloc[y,1] + '\n')
      

if len(str(sys.argv[1])) > 3 :
    name = str(sys.argv[1])
    split_pcap(name)
    convert_to_json(name)
    get_tshark_hexstreams(name)
    join_with_labeled_data(name)
    sliceNgram(name)
