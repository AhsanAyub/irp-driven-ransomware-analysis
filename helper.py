#!/usr/bin/env python3

__author__ = "Md. Ahsan Ayub"
__license__ = "GPL"
__credits__ = ["Ayub, Md. Ahsan", "Siraj, Ambareen"]
__maintainer__ = "Md. Ahsan Ayub"
__email__ = "mayub42@students.tntech.edu"
__status__ = "Prototype"

# Import libraries
import os
import glob

# Families for validation of threshold
test_ransomware_families = ['Bitman', 'Cerber', 'Kelios']


def get_all_ransomsomware_family_paths():
    ''' The function returns all the training ransomware families
    paths for further analysis '''
    
    cwd = os.getcwd()   # Current project working direction
    ransomware_all_family_name_paths = [x[0] for x in os.walk(str(cwd) + '/Dataset')]
    ransomware_all_family_name_paths = sorted(ransomware_all_family_name_paths)
    ransomware_all_family_name_paths.pop(0)    # Remove the dataset root folder
    
    return ransomware_all_family_name_paths


def get_ransomsomware_family_datasete_paths(family_path):
    ''' The function takes a ransomware family path and 
    returns all of its dataset files' names for further analysis '''
    
    ransomware_family_file_paths = [i for i in glob.glob(str(family_path) + '/*.gz')]
    
    return ransomware_family_file_paths


def get_test_ransomsomware_family_paths():
    ''' The function returns a certain set of ransomware families paths for
    validation of the thresholds for both time series and sequence mining analysis '''
    
    ransomware_all_family_name_paths = get_all_ransomsomware_family_paths()
    
    ransomware_test_family_name_paths = []   # To store the required file paths
    
    for i in range(len(ransomware_all_family_name_paths)):
        if (str(ransomware_all_family_name_paths[i]).split('/')[-1] in test_ransomware_families):
            ransomware_test_family_name_paths.append(ransomware_all_family_name_paths[i])
    
    return ransomware_test_family_name_paths


def get_train_ransomsomware_family_paths():
    ''' The function returns a certain set of ransomware families paths for
    training of the thresholds for both time series and sequence mining analysis '''
    
    ransomware_all_family_name_paths = get_all_ransomsomware_family_paths()
    
    ransomware_train_family_name_paths = []   # To store the required file paths
    
    for i in range(len(ransomware_all_family_name_paths)):
        if (str(ransomware_all_family_name_paths[i]).split('/')[-1] not in test_ransomware_families):
            ransomware_train_family_name_paths.append(ransomware_all_family_name_paths[i])
    
    return ransomware_train_family_name_paths