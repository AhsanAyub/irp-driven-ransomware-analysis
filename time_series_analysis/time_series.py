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
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

from time_series_analysis.attribute_container import (IRP_Operations_Container, Flags_Container, File_System_Container)
import time_series_analysis.time_series_visualization as visualiser


def build_attribute_containers(dataset_names):
    ''' Given the list of time chunk dataset names, this method will
    utilize attribute_container python file's classes to compile a master
    container of respective attributes for both benign and ransomware instances.'''
    
    # Dictionary to store the class objects for different time chunks
    containers = {}
    
    # Iterate through different dataset files
    for i in range(1,len(dataset_names)+1):
        ''' As the dataset names are not sorted properly, this hack will
        ensure the datasets are accessed serially '''
        
        for dataset_name in dataset_names:
            if(str(i) == str(dataset_name.split('_')[-1].split('.')[0])):
                ''' This is where the main operation will begin chronologically '''
                
                dataset = pd.read_pickle(dataset_name, compression='gzip')
                print(dataset.head())
                dataset = dataset.drop(['sequence_number', 'device_object', 'inform', 'arg1', 'arg2', 'arg3', 'arg4', 'arg5', 'arg6'], axis=1)
                dataset['irp_nocache'] = dataset['irp_nocache'].astype(int)
                dataset['irp_paging_io'] = dataset['irp_paging_io'].astype(int)
                dataset['irp_synchoronous_api'] = dataset['irp_synchoronous_api'].astype(int)
                dataset['irp_synchoronous_paging_io'] = dataset['irp_synchoronous_paging_io'].astype(int)
                
                # Separate benign and ransomware instances from the dataset
                benign_instances = dataset.drop(dataset[(dataset['class'] != 0)].index)
                ransomware_instances = dataset.drop(dataset[(dataset['class'] != 1)].index)
                del dataset
                

                ''' Process the dataset for IRP operations types '''
                benign_irp_operations_container = IRP_Operations_Container()
                ransomware_irp_operations_container = IRP_Operations_Container()
                
                # Set IRP operations for both types of datasets
                benign_irp_operations_container.set_operation_irp(benign_instances['operation_irp'].sum())
                ransomware_irp_operations_container.set_operation_irp(ransomware_instances['operation_irp'].sum())
                # Set FSF operations for both types of datasets
                benign_irp_operations_container.set_operation_fsf(benign_instances['operation_fsf'].sum())
                ransomware_irp_operations_container.set_operation_fsf(ransomware_instances['operation_fsf'].sum())
                # Set FSO operations for both types of datasets
                benign_irp_operations_container.set_operation_fio(benign_instances['operation_fio'].sum())
                ransomware_irp_operations_container.set_operation_fio(ransomware_instances['operation_fio'].sum())
                
                
                ''' Process the dataset for Flags varibles '''
                benign_flags_container = Flags_Container()
                ransomware_flags_container = Flags_Container()
                
                # Set IRP flag attributes for both types of datasets
                benign_irp_flags = {}
                benign_irp_flags['irp_flag'] = benign_instances['irp_flag'].unique().size
                benign_irp_flags['irp_nocache'] = benign_instances['irp_nocache'].sum()
                benign_irp_flags['irp_paging_io'] = benign_instances['irp_paging_io'].sum()
                benign_irp_flags['irp_synchoronous_api'] = benign_instances['irp_synchoronous_api'].sum()
                benign_irp_flags['irp_synchoronous_paging_io'] = benign_instances['irp_synchoronous_paging_io'].sum()
                benign_flags_container.set_irp_flags(benign_irp_flags)
                
                ransomware_irp_flags = {}
                ransomware_irp_flags['irp_flag'] = ransomware_instances['irp_flag'].unique().size
                ransomware_irp_flags['irp_nocache'] = ransomware_instances['irp_nocache'].sum()
                ransomware_irp_flags['irp_paging_io'] = ransomware_instances['irp_paging_io'].sum()
                ransomware_irp_flags['irp_synchoronous_api'] = ransomware_instances['irp_synchoronous_api'].sum()
                ransomware_irp_flags['irp_synchoronous_paging_io'] = ransomware_instances['irp_synchoronous_paging_io'].sum()
                ransomware_flags_container.set_irp_flags(ransomware_irp_flags)
                
                del benign_irp_flags, ransomware_irp_flags
                
                # Set IRP Major operation Type
                benign_flags_container.set_major_operation_type(benign_instances['major_operation_type'].unique().size)
                ransomware_flags_container.set_major_operation_type(ransomware_instances['major_operation_type'].unique().size)
                
                # Set IRP Minor operation Type
                benign_flags_container.set_minor_operation_type(benign_instances['minor_operation_type'].unique().size)
                ransomware_flags_container.set_minor_operation_type(ransomware_instances['minor_operation_type'].unique().size)
            
                # Set the status flag varible
                benign_flags_container.set_status(benign_instances['status'].unique().size)
                ransomware_flags_container.set_status(ransomware_instances['status'].unique().size)
                
                # Set the transaction flag varible
                benign_flags_container.set_transaction(benign_instances['transaction'].unique().size)
                ransomware_flags_container.set_transaction(ransomware_instances['transaction'].unique().size)
                
                
                ''' Process the dataset for file system attributes '''
                benign_file_system_container = File_System_Container()
                ransomware_file_system_container = File_System_Container()
                
                # Set File object variable
                benign_file_system_container.set_file_object(benign_instances['file_object'].unique().size)
                ransomware_file_system_container.set_file_object(ransomware_instances['file_object'].unique().size)
                
                # Set file accessed variable
                benign_file_system_container.set_file_accessed(benign_instances['file_name'].unique().size)
                ransomware_file_system_container.set_file_accessed(ransomware_instances['file_name'].unique().size)
                
                # Set different metrics from buffer length
                benign_file_system_container.set_buffer_length(benign_instances['buffer_length'])
                ransomware_file_system_container.set_buffer_length(ransomware_instances['buffer_length'])
                
                # Set different metrics from entropy
                benign_file_system_container.set_entropy(benign_instances['entropy'])
                ransomware_file_system_container.set_entropy(ransomware_instances['entropy'])
                
                containers[str(i)] = {
                        "benign" : [benign_irp_operations_container, benign_flags_container, benign_file_system_container],
                        "ransomware" : [ransomware_irp_operations_container, ransomware_flags_container, ransomware_file_system_container]
                        }
                
                del benign_instances, ransomware_instances

    return containers


def build_process_wise_file_system_container(dataset_names):
    ''' Given the list of time chunk dataset names, this method will
    utilize attribute_container python file's File_System_Container class
    to compile a master container of such attributes for both benign processes
    (having the highest count given a time frame) and ransomware process.'''

    # Dictionary to store the class objects for different time chunks
    file_system_container = {}
    
    # Iterate through different dataset files
    for i in range(1,len(dataset_names)+1):
        ''' As the dataset names are not sorted properly, this hack will
        ensure the datasets are accessed serially '''
        
        for dataset_name in dataset_names:
            if(str(i) == str(dataset_name.split('_')[-1].split('.')[0])):
                ''' This is where the main operation will begin chronologically '''
                
                dataset = pd.read_pickle(dataset_name, compression='gzip')
                print(dataset.head())
    
                ''' Selection only features that are needed to analyze file system analysis '''
                dataset = dataset[['process_id', 'process_name', 'file_object','file_name','buffer_length','entropy','class']]
                
                # Group by process id and process name to fetch the benign process representative
                groupedData = dataset.groupby(['process_id', 'process_name'])
                
                # Only selecting onc process that has got hightest sum of buffer length
                benign_process_id = -1
                benign_process_name = ''
                temp_max_buffer_length = 0
                
                benign_file_system_container = File_System_Container()
                ransomware_file_system_container = File_System_Container()
                
                # As ransomware may incorporate multiple processes, we will consider its every record
                ransomware_instances = dataset.drop(dataset[(dataset['class'] != 1)].index)
                ransomware_file_system_container.set_file_object(ransomware_instances['file_object'].unique().size)
                ransomware_file_system_container.set_file_accessed(ransomware_instances['file_name'].unique().size)
                ransomware_file_system_container.set_buffer_length(ransomware_instances['buffer_length'])
                ransomware_file_system_container.set_entropy(ransomware_instances['entropy'])
                
                # Find out the benign process representative
                for items in groupedData:
                    if items[1]['class'].sum() > 0:
                        pass    # Ransomware process
                    else:   # Benign process
                        if(items[1]['buffer_length'].max() > temp_max_buffer_length):
                            temp_max_buffer_length = items[1]['buffer_length'].max()
                            benign_process_id = items[0][0]
                            benign_process_name = items[0][1]
                        else:
                            pass
                
                # Got the desired benign process representative
                for items in groupedData:
                    if (items[0][0] == benign_process_id) and (items[0][1] == benign_process_name):
                        # Benign process
                        benign_file_system_container.set_file_object(items[1]['file_object'].unique().size)
                        benign_file_system_container.set_file_accessed(items[1]['file_name'].unique().size)
                        benign_file_system_container.set_buffer_length(items[1]['buffer_length'])
                        benign_file_system_container.set_entropy(items[1]['entropy'])
                        
                    else:
                        pass
                    
                file_system_container[i] = { "benign" : benign_file_system_container,
                                             "ransomware" : ransomware_file_system_container}
                
            else:
                pass
    
    # Return the container having all the objects        
    return file_system_container
    

if __name__ == '__main__':
    
    cwd = os.getcwd()   # Current project working direction
    
    '''# Get the feature containers of all the 5 mins time chunk datasets
    containers = build_attribute_containers([i for i in glob.glob(str(cwd) + '/Dataset/TeslaCrypt/' + '*.gz')])

    visualiser.self_irp_operations_analysis(containers, "TeslaCrypt")
    visualiser.self_irp_flags_analysis(containers, "TeslaCrypt")
    visualiser.self_file_system_analysis(containers, "TeslaCrypt")
    
    file_system_container = build_process_wise_file_system_container([i for i in glob.glob(str(cwd) + '/Dataset/TeslaCrypt/' + '*.gz')])
    visualiser.comparitive_file_system_analysis_individual_family(file_system_container, "TeslaCrypt")'''
    
    ransomware_family_name_paths = [x[0] for x in os.walk(str(cwd) + '/Dataset')]
    ransomware_family_name_paths = sorted(ransomware_family_name_paths)
    ransomware_family_name_paths.pop(0)    # Remove the dataset root folder
    master_container = {}
    
    for ransomware_family_name_path in ransomware_family_name_paths:
        master_container[str(ransomware_family_name_path).split('/')[-1]] = build_attribute_containers([i for i in glob.glob(str(ransomware_family_name_path) + '/*.gz')])
        
    # ---- Box plots for file system container ----
    file_object = {}
    unique_file_accessed = {}
    entropy = {}
    buffer_length = {}
    ransomware_family_names = []
    
    for ransomware_family in master_container:
        ''' Temporary lists to populate the values for box plot '''
        temp_file_object = []
        temp_unique_file_accessed = []
        temp_entropy = []
        temp_buffer_length = []
        
        for key in master_container[ransomware_family]:
            for objects in master_container[ransomware_family][key]['ransomware']:
                if isinstance(objects, File_System_Container):
                    temp_file_object.append(objects.get_file_object())
                    temp_unique_file_accessed.append(objects.get_file_accessed())
                    temp_buffer_length.append(objects.get_buffer_length()['mean_buffer_length'])
                    temp_entropy.append(objects.get_entropy()['mean_entropy'])
                    
                else:
                    pass
        
        file_object[str(ransomware_family)] = temp_file_object
        unique_file_accessed[str(ransomware_family)] = temp_unique_file_accessed
        entropy[str(ransomware_family)] = temp_entropy
        buffer_length[str(ransomware_family)] = temp_buffer_length
        ransomware_family_names.append(str(ransomware_family))
        
    del temp_file_object, temp_unique_file_accessed, temp_entropy, temp_buffer_length
    
    
    # --- Print file object box plot ---
    data = []    
    for i in range(18):
        temp = []
        for ransomware_family_name in ransomware_family_names:
            try:
                temp.append(file_object[ransomware_family_name][i])
            except:
                #temp.append(0)
                continue
        data.append(temp)
    del temp
    visualiser.generate_simple_box_plot(data, "File Object Feature Distribution among Ransomware Families", "Unique Counts")
    
    # --- Print file accessed box plot ---
    data = []    
    for i in range(18):
        temp = []
        for ransomware_family_name in ransomware_family_names:
            try:
                temp.append(unique_file_accessed[ransomware_family_name][i])
            except:
                continue
        data.append(temp)
    del temp
    visualiser.generate_simple_box_plot(data, "Number of Files Accessed by Ransomware Families", "Unique Counts")
    
    # --- Print entropy box plot ---
    data = []    
    for i in range(18):
        temp = []
        for ransomware_family_name in ransomware_family_names:
            try:
                temp.append(entropy[ransomware_family_name][i] * 100)
            except:
                continue
        data.append(np.log(temp))
    del temp
    visualiser.generate_simple_box_plot(data, "Entropy Feature Distribution among Ransomware Families", "Logarithm Values of Mean")
    
    # --- Print buffer length box plot ---
    data = []    
    for i in range(18):
        temp = []
        for ransomware_family_name in ransomware_family_names:
            try:
                temp.append(buffer_length[ransomware_family_name][i])
            except:
                continue
        data.append(np.log(temp))
    del temp
    visualiser.generate_simple_box_plot(data, "Buffer Length Feature Distribution among Ransomware Families", "Logarithm Values of Mean")