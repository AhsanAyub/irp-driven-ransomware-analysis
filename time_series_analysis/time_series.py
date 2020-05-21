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
import math
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from time_series_analysis.attribute_container import (IRP_Operations_Container, Flags_Container, File_System_Container)


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


def self_irp_operations_analysis(container, family_name):
    ''' visualize the types of the IRP operations count for a single ransomware family '''
    
    time_intervals = []
    ransomware_irp_operations = []
    ransomware_fsf_operations = []
    ransomware_fio_operations = []
    
    for time_interval in containers:
        time_intervals.append(int(time_interval) * 5)
        for objects in containers[time_interval]['ransomware']:
            if isinstance(objects, IRP_Operations_Container):
                ransomware_irp_operations.append(math.log(objects.get_operation_irp())) if objects.get_operation_irp() > 0 else ransomware_irp_operations.append(0)
                ransomware_fsf_operations.append(math.log(objects.get_operation_fsf())) if objects.get_operation_fsf() > 0 else ransomware_fsf_operations.append(0)
                ransomware_fio_operations.append(math.log(objects.get_operation_fio())) if objects.get_operation_fio() > 0 else ransomware_fio_operations.append(0)
                
    # --- Time Series Plot of Types of IRP Operations --- 
    
    myFig = plt.figure(figsize=[12,10])
    plt.plot(ransomware_irp_operations, linestyle = 'dashdot', marker = 'o', lw = 2, alpha=0.8, color = 'black')
    plt.plot(ransomware_fsf_operations, linestyle = 'dashed', marker = 'o', lw = 2, alpha=0.8, color = 'black')
    plt.plot(ransomware_fio_operations, linestyle = 'dotted', marker = 'o', lw = 2, alpha=0.8, color = 'black')
    plt.xticks(range(len(time_intervals)), time_intervals, fontsize=16)
    plt.title('Time Series Plot of Types of IRP Operations (' + str(family_name) + ')', fontsize=20, weight='bold')
    plt.ylabel('Logarithm Values', fontsize=18, weight='bold')
    plt.xlabel('Time (in minutes)', fontsize=18, weight='bold')
    plt.legend(['IRP', 'FSF', 'FIO'] , loc='best', fontsize=14)
    plt.yticks(fontsize=16)
    plt.show()
        
    # Saving the figure
    myFig.savefig('time_series_analysis/Results/' + str(family_name) + '_Types_of_IRP_Operations.eps', format='eps', dpi=1200)
    myFig.savefig('time_series_analysis/Results/' + str(family_name) + '_Types_of_IRP_Operations.png', format='png', dpi=600)


def self_irp_flags_analysis(container, family_name):
    ''' visualize the types of the IRP flags counts for a single ransomware family '''
    
    time_intervals = []
    ransomware_irp_flags = {}
    
    for time_interval in containers:
        time_intervals.append(int(time_interval) * 5)
        for objects in containers[time_interval]['ransomware']:
            if isinstance(objects, Flags_Container):
                ransomware_irp_flags[int(time_interval)] = objects.get_irp_flags()
                
    ransomware_irp_flags = pd.DataFrame(ransomware_irp_flags).T
    
    myFig = plt.figure(figsize=[12,10])
    plt.plot(np.log(ransomware_irp_flags.irp_nocache), linestyle = 'solid', marker = 'v', lw = 2, alpha=0.8, color = 'black')
    plt.plot(np.log(ransomware_irp_flags.irp_paging_io), linestyle = 'dotted', marker = 'o', lw = 2, alpha=0.8, color = 'black')
    plt.plot(np.log(ransomware_irp_flags.irp_synchoronous_api), linestyle = 'dashed', marker = 's', lw = 2, alpha=0.8, color = 'black')
    plt.plot(np.log(ransomware_irp_flags.irp_synchoronous_paging_io), linestyle = 'dashdot', marker = '^', lw = 2, alpha=0.8, color = 'black')
    plt.xticks(range(len([i * 5 for i in range(len(ransomware_irp_flags.irp_synchoronous_paging_io)+1)])),
               [i * 5 for i in range(len(ransomware_irp_flags.irp_synchoronous_paging_io)+1)], fontsize=16) # A hack for God knows what problem
    plt.title('Time Series Plot of IRP Flags (' + str(family_name) + ')', fontsize=20, weight='bold')
    plt.ylabel('Logarithm Values', fontsize=18, weight='bold')
    plt.xlabel('Time (in minutes)', fontsize=18, weight='bold')
    plt.legend(['NoCache', 'Paging IO', 'Synchoronous API', 'Synchoronous Paging IO'] , loc='best', fontsize=14)
    plt.yticks(fontsize=16)
    plt.show()
        
    # Saving the figure
    myFig.savefig('time_series_analysis/Results/' + str(family_name) + '_IRP_Flags.eps', format='eps', dpi=1200)
    myFig.savefig('time_series_analysis/Results/' + str(family_name) + '_IRP_Flags.png', format='png', dpi=600)
    
    
def self_file_system_analysis(container, family_name):
    ''' visualize the features of the file system category '''
    
    time_intervals = []
    ransomware_file_objects = []
    benign_file_objects = []
    ransomware_file_accessed = []
    benign_file_accessed = []
    ransomware_buffer_lengths = {}
    ransomware_entropy = {}
    benign_entropy = {}
    
    for time_interval in containers:
        time_intervals.append(int(time_interval) * 5)
        for objects in containers[time_interval]['ransomware']:
            if isinstance(objects, File_System_Container):
                ransomware_file_objects.append(objects.get_file_object())
                ransomware_file_accessed.append(objects.get_file_accessed())
                ransomware_buffer_lengths[int(time_interval)] = objects.get_buffer_length()
                ransomware_entropy[int(time_interval)] = objects.get_entropy()
                
            else:
                pass
            
        for objects in containers[time_interval]['benign']:
            if isinstance(objects, File_System_Container):
                benign_file_objects.append(objects.get_file_object())
                benign_file_accessed.append(objects.get_file_accessed())
                benign_entropy[int(time_interval)] = objects.get_entropy()
                
            else:
                pass
                
    ransomware_buffer_lengths = pd.DataFrame(ransomware_buffer_lengths).T
    ransomware_entropy = pd.DataFrame(ransomware_entropy).T
    benign_entropy = pd.DataFrame(benign_entropy).T
    
    # --- Time Series Plot of both type of file objects --- 
    
    myFig = plt.figure(figsize=[12,10])
    plt.plot(np.log(ransomware_file_objects), linestyle = 'dotted', marker = 'o', lw = 2, alpha=0.8, color = 'black')
    plt.plot(np.log(benign_file_objects), linestyle = 'dashed', marker = 's', lw = 2, alpha=0.8, color = 'black')
    plt.xticks(range(len(time_intervals)), time_intervals, fontsize=16)
    plt.title('Time Series Plot of File Objects (' + str(family_name) + ')', fontsize=20, weight='bold')
    plt.ylabel('Logarithm Values', fontsize=18, weight='bold')
    plt.xlabel('Time (in minutes)', fontsize=18, weight='bold')
    plt.legend(['Ransomware', 'Benign'] , loc='best', fontsize=14)
    plt.yticks(fontsize=16)
    plt.show()
        
    # Saving the figure
    myFig.savefig('time_series_analysis/Results/' + str(family_name) + '_File_Objects.eps', format='eps', dpi=1200)
    myFig.savefig('time_series_analysis/Results/' + str(family_name) + '_File_Objects.png', format='png', dpi=600)
    
    # --- Time Series Plot of both type of file accessed --- 
    
    myFig = plt.figure(figsize=[12,10])
    plt.plot(np.log(ransomware_file_accessed), linestyle = 'dotted', marker = 'o', lw = 2, alpha=0.8, color = 'black')
    plt.plot(np.log(benign_file_accessed), linestyle = 'dashed', marker = 's', lw = 2, alpha=0.8, color = 'black')
    plt.xticks(range(len(time_intervals)), time_intervals, fontsize=16)
    plt.title('Time Series Plot of Unique File Accessed (' + str(family_name) + ')', fontsize=20, weight='bold')
    plt.ylabel('Logarithm Values', fontsize=18, weight='bold')
    plt.xlabel('Time (in minutes)', fontsize=18, weight='bold')
    plt.legend(['Ransomware', 'Benign'] , loc='best', fontsize=14)
    plt.yticks(fontsize=16)
    plt.show()
        
    # Saving the figure
    myFig.savefig('time_series_analysis/Results/' + str(family_name) + '_File_Accessed.eps', format='eps', dpi=1200)
    myFig.savefig('time_series_analysis/Results/' + str(family_name) + '_File_Accessed.png', format='png', dpi=600)
    
    # --- Time Series Plot of ransomware buffer length --- 
    
    myFig = plt.figure(figsize=[12,10])
    plt.plot(np.log(ransomware_buffer_lengths.max_buffer_length), linestyle = 'dotted', marker = 'o', lw = 2, alpha=0.8, color = 'black')
    plt.plot(np.log(ransomware_buffer_lengths.mean_buffer_length), linestyle = 'dashed', marker = 's', lw = 2, alpha=0.8, color = 'black')
    plt.xticks(range(len([i * 5 for i in range(len(ransomware_buffer_lengths.mean_buffer_length)+1)])),
               [i * 5 for i in range(len(ransomware_buffer_lengths.mean_buffer_length)+1)], fontsize=16) # A hack for God knows what problem
    plt.title('Time Series Plot of Buffer Length (' + str(family_name) + ')', fontsize=20, weight='bold')
    plt.ylabel('Logarithm Values', fontsize=18, weight='bold')
    plt.xlabel('Time (in minutes)', fontsize=18, weight='bold')
    plt.legend(['Max', 'Mean'] , loc='best', fontsize=14)
    plt.yticks(fontsize=16)
    plt.show()
        
    # Saving the figure
    myFig.savefig('time_series_analysis/Results/' + str(family_name) + '_Buffer_Length.eps', format='eps', dpi=1200)
    myFig.savefig('time_series_analysis/Results/' + str(family_name) + '_Buffer_Length.png', format='png', dpi=600)
    
    # --- Time Series Plot of ransomware entropy --- 
    
    myFig = plt.figure(figsize=[12,10])
    plt.plot(np.log(ransomware_entropy.mean_entropy * 100), linestyle = 'dotted', marker = 'o', lw = 2, alpha=0.8, color = 'black')
    plt.plot(np.log(benign_entropy.mean_entropy * 100), linestyle = 'dashed', marker = 's', lw = 2, alpha=0.8, color = 'black')
    plt.xticks(range(len([i * 5 for i in range(len(ransomware_entropy.mean_entropy )+1)])),
               [i * 5 for i in range(len(ransomware_entropy.mean_entropy )+1)], fontsize=16) # A hack for God knows what problem
    plt.title('Time Series Plot of Entropy (' + str(family_name) + ')', fontsize=20, weight='bold')
    plt.ylabel('Logarithm Values', fontsize=18, weight='bold')
    plt.xlabel('Time (in minutes)', fontsize=18, weight='bold')
    plt.legend(['Ransomware', 'Benign'] , loc='best', fontsize=14)
    plt.yticks(fontsize=16)
    plt.show()
        
    # Saving the figure
    myFig.savefig('time_series_analysis/Results/' + str(family_name) + '_Entropy.eps', format='eps', dpi=1200)
    myFig.savefig('time_series_analysis/Results/' + str(family_name) + '_Entropy.png', format='png', dpi=600)


if __name__ == '__main__':
    
    cwd = os.getcwd()   # Current project working direction
    
    # Get the feature containers of all the 5 mins time chunk datasets
    containers = build_attribute_containers([i for i in glob.glob(str(cwd) + '/Dataset/' + '*.gz')])

    self_irp_operations_analysis(containers, "CryptoDefense")
    self_irp_flags_analysis(containers, "CryptoDefense")
    self_file_system_analysis(containers, "CryptoDefense")