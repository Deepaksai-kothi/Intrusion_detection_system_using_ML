# Intrusion_detection_system_using_ML
This project uses randomforest ml model to detect various attacks including DOS, PROBE etc. uses various python modules like pyshark to capture packets and reflects detected attacks onto frontend

# SET_UP of projecct

# 1 use a virtual desktop (system 1, windows. preferred for optimal performance use--> vmware workstatio)
# 2 set up virtual windows machine using vmware set network connectionn to bridge with host system so, to seccure and use ip for attack
# 3 set up another virtual machine (system 2, Kali linux to simulate attacks)
# 4 use both VM's in same host make an organized side by side window system-1, system-2
# 5 ping your virtual windows (system-1) using kali linux(system-2). use command "sudo ping your_windows_ip" (note: disable firewall in windows vm to proceed further. so,use virtual machinne)
# 6 after ping sucessfully established procceed further by using various attacks on kali liux using target ip (system-1)
# 7 this is just simulation so use Virtal macchine, now you can use IDS project on Windows(system-1), to detect attacks (note: only detects does not prevent or take action)

# USING PROJECT IN WINDOWS

# STEP 1--> Use NSS-KDD.csv data set from kaggle use link: https://www.kaggle.com/datasets/hassan06/nslkdd or use data set NSS-KDD.csv from repository.
# STEP 2--> Train and test dataset using RandomForest.py which also creates random_forest_model.pkl which is a trained model redy to use for prediction. (which will use further for detection.)

--># (DONONT MISS IMP)before next step start attack with kali liux(System-2) on Windows (system-1, which runs project) which will create abnormal packets then immediatly run next step

# STEP 3--> Next run featurs.py this creates a network_features.csv file which contais required features for detecting,
          and this is main step as it actually captures live packets using pyshark module in python(Note: make chages in features.py at 
          # Live capture from network interface (Update if needed according to your interface)
            cap = pyshark.LiveCapture(interface="Ethernet0")

# STEP 4--> alternately you can also use pcap.py to get features from pcap file which is file generated when downloaded from live capture of packets in wireshark

# STEP 5--> run project_server.py(main) which creates local server for web page, open web page uploade the csv file i.e which we get from STEP 3 or STEP 4 
the front end shows the attacks that came from kali liux and it detects accurately

# you can customize web page and  background  @templates and @static 
//crucial Homepage.html has functionalities customize without breaking//

