#!/usr/bin/env python3

__author__ = "Md. Ahsan Ayub"
__license__ = "GPL"
__credits__ = ["Ayub, Md. Ahsan", "Siraj, Ambareen"]
__maintainer__ = "Md. Ahsan Ayub"
__email__ = "mayub42@students.tntech.edu"
__status__ = "Prototype"

# import libraries
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import math

from time_series_analysis.attribute_container import (IRP_Operations_Container, Flags_Container, File_System_Container)

def self_irp_operations_analysis(container, family_name):
    ''' visualize the types of the IRP operations count for a single ransomware family '''
    
    time_intervals = []
    ransomware_irp_operations = []
    ransomware_fsf_operations = []
    ransomware_fio_operations = []
    
    for time_interval in container:
        time_intervals.append(int(time_interval) * 5)
        for objects in container[time_interval]['ransomware']:
            if isinstance(objects, IRP_Operations_Container):
                ransomware_irp_operations.append(math.log(objects.get_operation_irp())) if objects.get_operation_irp() > 0 else ransomware_irp_operations.append(0)
                ransomware_fsf_operations.append(math.log(objects.get_operation_fsf())) if objects.get_operation_fsf() > 0 else ransomware_fsf_operations.append(0)
                ransomware_fio_operations.append(math.log(objects.get_operation_fio())) if objects.get_operation_fio() > 0 else ransomware_fio_operations.append(0)
                
    # --- Time Series Plot of Types of IRP Operations --- 
    
    plt.clf() # Clear figure
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
    myFig.savefig('time_series_analysis/Results/' + str(family_name) + '_Types_of_IRP_Operations.png', format='png', dpi=300)


def self_irp_flags_analysis(container, family_name):
    ''' visualize the types of the IRP flags counts for a single ransomware family '''
    
    time_intervals = []
    ransomware_irp_flags = {}
    
    for time_interval in container:
        time_intervals.append(int(time_interval) * 5)
        for objects in container[time_interval]['ransomware']:
            if isinstance(objects, Flags_Container):
                ransomware_irp_flags[int(time_interval)] = objects.get_irp_flags()
                
    ransomware_irp_flags = pd.DataFrame(ransomware_irp_flags).T
    
    plt.clf() # Clear figure
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
    myFig.savefig('time_series_analysis/Results/' + str(family_name) + '_IRP_Flags.png', format='png', dpi=300)
    
    
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
    
    for time_interval in container:
        time_intervals.append(int(time_interval) * 5)
        for objects in container[time_interval]['ransomware']:
            if isinstance(objects, File_System_Container):
                ransomware_file_objects.append(objects.get_file_object())
                ransomware_file_accessed.append(objects.get_file_accessed())
                ransomware_buffer_lengths[int(time_interval)] = objects.get_buffer_length()
                ransomware_entropy[int(time_interval)] = objects.get_entropy()
                
            else:
                pass
            
        for objects in container[time_interval]['benign']:
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
    
    plt.clf() # Clear figure
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
    myFig.savefig('time_series_analysis/Results/' + str(family_name) + '_File_Objects.png', format='png', dpi=300)
    
    # --- Time Series Plot of both type of file accessed --- 
    
    plt.clf() # Clear figure
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
    myFig.savefig('time_series_analysis/Results/' + str(family_name) + '_File_Accessed.png', format='png', dpi=300)
    
    # --- Time Series Plot of ransomware buffer length --- 
    
    plt.clf() # Clear figure
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
    myFig.savefig('time_series_analysis/Results/' + str(family_name) + '_Buffer_Length.png', format='png', dpi=300)
    
    # --- Time Series Plot of ransomware entropy --- 
    
    plt.clf() # Clear figure
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
    myFig.savefig('time_series_analysis/Results/' + str(family_name) + '_Entropy.png', format='png', dpi=300)
    

def comparitive_file_system_analysis_individual_family(container, family_name):
    ''' visualize the features of the file system category
        This is where we will be comparing ransomware process with
        one of the benign process in the dataset. '''
    
    time_intervals = []
    ransomware_file_objects = []
    benign_file_objects = []
    ransomware_file_accessed = []
    benign_file_accessed = []
    ransomware_buffer_lengths = {}
    benign_buffer_lengths = {}
    ransomware_entropy = {}
    benign_entropy = {}
    
    for time_interval in container:
        time_intervals.append(int(time_interval) * 5)
        
        ransomware_object = container[time_interval]['ransomware']
        ransomware_file_objects.append(ransomware_object.get_file_object())
        ransomware_file_accessed.append(ransomware_object.get_file_accessed())
        ransomware_buffer_lengths[int(time_interval)] = ransomware_object.get_buffer_length()
        ransomware_entropy[int(time_interval)] = ransomware_object.get_entropy()
            
        benign_object = container[time_interval]['benign']
        benign_file_objects.append(benign_object.get_file_object())
        benign_file_accessed.append(benign_object.get_file_accessed())
        benign_buffer_lengths[int(time_interval)] = benign_object.get_buffer_length()
        benign_entropy[int(time_interval)] = benign_object.get_entropy()
                
    ransomware_buffer_lengths = pd.DataFrame(ransomware_buffer_lengths).T
    benign_buffer_lengths = pd.DataFrame(benign_buffer_lengths).T
    ransomware_entropy = pd.DataFrame(ransomware_entropy).T
    benign_entropy = pd.DataFrame(benign_entropy).T
    
    # --- Time Series Plot of both type of file objects --- 
    
    plt.clf() # Clear figure
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
    myFig.savefig('time_series_analysis/Results/' + str(family_name) + '_File_Objects_comparitive_individual_family.eps', format='eps', dpi=1200)
    myFig.savefig('time_series_analysis/Results/' + str(family_name) + '_File_Objects_comparitive_individual_family.png', format='png', dpi=300)
    
    # --- Time Series Plot of both type of file accessed --- 
    
    plt.clf() # Clear figure
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
    myFig.savefig('time_series_analysis/Results/' + str(family_name) + '_File_Accessed_comparitive_individual_family.eps', format='eps', dpi=1200)
    myFig.savefig('time_series_analysis/Results/' + str(family_name) + '_File_Accessed_comparitive_individual_family.png', format='png', dpi=300)
    
    # --- Time Series Plot of ransomware buffer length --- 
    
    plt.clf() # Clear figure
    myFig = plt.figure(figsize=[12,10])
    plt.plot(np.log(ransomware_buffer_lengths.mean_buffer_length), linestyle = 'dotted', marker = 'o', lw = 2, alpha=0.8, color = 'black')
    plt.plot(np.log(benign_buffer_lengths.mean_buffer_length), linestyle = 'dashed', marker = 's', lw = 2, alpha=0.8, color = 'black')
    plt.xticks(range(len([i * 5 for i in range(len(ransomware_buffer_lengths.mean_buffer_length)+1)])),
               [i * 5 for i in range(len(ransomware_buffer_lengths.mean_buffer_length)+1)], fontsize=16) # A hack for God knows what problem
    plt.title('Time Series Plot of Buffer Length (' + str(family_name) + ')', fontsize=20, weight='bold')
    plt.ylabel('Logarithm Values', fontsize=18, weight='bold')
    plt.xlabel('Time (in minutes)', fontsize=18, weight='bold')
    plt.legend(['Ransomware', 'Benign'] , loc='best', fontsize=14)
    plt.yticks(fontsize=16)
    plt.show()
        
    # Saving the figure
    myFig.savefig('time_series_analysis/Results/' + str(family_name) + '_Buffer_Length_comparitive_individual_family.eps', format='eps', dpi=1200)
    myFig.savefig('time_series_analysis/Results/' + str(family_name) + '_Buffer_Length_comparitive_individual_family.png', format='png', dpi=300)
    
    # --- Time Series Plot of ransomware entropy --- 
    
    plt.clf() # Clear figure
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
    myFig.savefig('time_series_analysis/Results/' + str(family_name) + '_Entropy_comparitive_individual_family.eps', format='eps', dpi=1200)
    myFig.savefig('time_series_analysis/Results/' + str(family_name) + '_Entropy_comparitive_individual_family.png', format='png', dpi=300)


def generate_feature_median_value_from_dic(feature_dict, ransomware_family_names):
    ''' Given a dictionary, generate the median value of the rows '''
    
    median_list = []
    
    for i in range(18):
        temp_list = []
        for family in ransomware_family_names:
            try:
                temp_list.append(feature_dict[family][i])
            except:
                continue
        median_list.append(np.median(temp_list))
        print(median_list[i])
    
    return median_list


def combined_file_system_feature_distribution_ransomware_and_benign(master_container):
    ''' This function will take the master container where all the ransomware families
    names are key, its values are dictionary. The second dictionary contains time
    frames as keys while the objects of classes as values.
    
    From the object, the function goes through all the file system objects to generate
    different time series graph between ransomware (all families combined) and benign. '''
    
    ransomware_family_names = []
    
    # File System features for further analysis
    ransomware_file_object = {}
    ransomware_unique_file_accessed = {}
    ransomware_entropy = {}
    ransomware_buffer_length = {}
    
    benign_file_object = {}
    benign_unique_file_accessed = {}
    benign_entropy = {}
    benign_buffer_length = {}
    
    for ransomware_family in master_container:
        # Temporary lists to populate the values for File System features
        ransomware_temp_file_object = []
        ransomware_temp_unique_file_accessed = []
        ransomware_temp_entropy = []
        ransomware_temp_buffer_length = []
        
        benign_temp_file_object = []
        benign_temp_unique_file_accessed = []
        benign_temp_entropy = []
        benign_temp_buffer_length = []
        
        # Iterate through the master container to populate the dictionaries
        for key in master_container[ransomware_family]:
            for objects in master_container[ransomware_family][key]['ransomware']:
                if isinstance(objects, File_System_Container): # Needed for file system features
                    ransomware_temp_file_object.append(objects.get_file_object())
                    ransomware_temp_unique_file_accessed.append(objects.get_file_accessed())
                    ransomware_temp_entropy.append(objects.get_entropy()['mean_entropy'])
                    ransomware_temp_buffer_length.append(objects.get_buffer_length()['mean_buffer_length'])
                    
                else:
                    pass
                
            for objects in master_container[ransomware_family][key]['benign']:
                if isinstance(objects, File_System_Container): # Needed for file system features
                    benign_temp_file_object.append(objects.get_file_object())
                    benign_temp_unique_file_accessed.append(objects.get_file_accessed())
                    benign_temp_entropy.append(objects.get_entropy()['mean_entropy'])
                    benign_temp_buffer_length.append(objects.get_buffer_length()['mean_buffer_length'])
                    
                else:
                    pass
        
        ransomware_family_names.append(str(ransomware_family))  # This list will contain the list of families
        
        # Populate dictionaries where the keys are ransoware family names
        ransomware_file_object[str(ransomware_family)] = ransomware_temp_file_object
        ransomware_unique_file_accessed[str(ransomware_family)] = ransomware_temp_unique_file_accessed
        ransomware_entropy[str(ransomware_family)] = ransomware_temp_entropy
        ransomware_buffer_length[str(ransomware_family)] = ransomware_temp_buffer_length
        
        benign_file_object[str(ransomware_family)] = benign_temp_file_object
        benign_unique_file_accessed[str(ransomware_family)] = benign_temp_unique_file_accessed
        benign_entropy[str(ransomware_family)] = benign_temp_entropy
        benign_buffer_length[str(ransomware_family)] = benign_temp_buffer_length
        
    # Delete all the temp lists
    del (ransomware_temp_file_object, ransomware_temp_unique_file_accessed, ransomware_temp_entropy, ransomware_temp_buffer_length,
    benign_temp_file_object, benign_temp_unique_file_accessed, benign_temp_entropy, benign_temp_buffer_length)
    
    ransomware_file_object['median'] = generate_feature_median_value_from_dic(ransomware_file_object, ransomware_family_names)
    ransomware_unique_file_accessed['median'] = generate_feature_median_value_from_dic(ransomware_unique_file_accessed, ransomware_family_names)
    ransomware_entropy['median'] = generate_feature_median_value_from_dic(ransomware_entropy, ransomware_family_names)
    ransomware_buffer_length['median'] = generate_feature_median_value_from_dic(ransomware_buffer_length, ransomware_family_names)
    
    benign_file_object['median'] = generate_feature_median_value_from_dic(benign_file_object, ransomware_family_names)
    benign_unique_file_accessed['median'] = generate_feature_median_value_from_dic(benign_unique_file_accessed, ransomware_family_names)
    benign_entropy['median'] = generate_feature_median_value_from_dic(benign_entropy, ransomware_family_names)
    benign_buffer_length['median'] = generate_feature_median_value_from_dic(benign_buffer_length, ransomware_family_names)
    
    time_intervals = [i * 5 for i in range(1,19)]
    
    # --- Time Series Plot of File Object Feature (Ransomware vs Benign) ---
    plt.clf() # Clear figure
    myFig = plt.figure(figsize=[12,10])
    plt.plot(ransomware_file_object['median'], linestyle = 'dotted', marker = 'o', lw = 2, alpha=0.8, color = 'black')
    plt.plot(benign_file_object['median'], linestyle = 'dashed', marker = 's', lw = 2, alpha=0.8, color = 'black')
    plt.xticks(range(len(time_intervals)), time_intervals, fontsize=16)
    for ii in range(18):
        plt.text(ii-0.5, np.min(benign_file_object['median'])-100, format(int(ransomware_file_object['median'][ii]-benign_file_object['median'][ii]), ',d'), size=10, weight='bold')
    plt.fill_between([i for i in range(18)], ransomware_file_object['median'], benign_file_object['median'], color="grey", alpha="0.3")
    plt.title('Time Series Plot of File Object Feature', fontsize=20, weight='bold')
    plt.ylabel('Median Counts', fontsize=18, weight='bold')
    plt.xlabel('Time (in minutes)', fontsize=18, weight='bold')
    plt.legend(['Ransomware', 'Benign'] , loc='best', fontsize=14)
    plt.ylim(np.min(benign_file_object['median'])-200, np.max(ransomware_file_object['median'])+200)
    plt.yticks(fontsize=16)
    plt.show()
    
    # Saving the figure
    myFig.savefig('time_series_analysis/Results/Combined/Time_Series_Plot/File_Object_Feature_Ransomware_vs_Benign.eps', format='eps', dpi=1200)
    myFig.savefig('time_series_analysis/Results/Combined/Time_Series_Plot/File_Object_Feature_Ransomware_vs_Benign.png', format='png', dpi=150)
    
    # --- Time Series Plot of Unique Files Accessed (Ransomware vs Benign) ---
    plt.clf() # Clear figure
    myFig = plt.figure(figsize=[12,10])
    plt.plot(ransomware_unique_file_accessed['median'], linestyle = 'dotted', marker = 'o', lw = 2, alpha=0.8, color = 'black')
    plt.plot(benign_unique_file_accessed['median'], linestyle = 'dashed', marker = 's', lw = 2, alpha=0.8, color = 'black')
    plt.xticks(range(len(time_intervals)), time_intervals, fontsize=16)
    for ii in range(18):
        plt.text(ii-0.5, 0, format(int(ransomware_unique_file_accessed['median'][ii]-benign_unique_file_accessed['median'][ii]), ',d'), size=10, weight='bold')
    plt.fill_between([i for i in range(18)], ransomware_unique_file_accessed['median'], benign_unique_file_accessed['median'], color="grey", alpha="0.3")
    plt.title('Time Series Plot of Unique Files Accessed', fontsize=20, weight='bold')
    plt.ylabel('Median Counts', fontsize=18, weight='bold')
    plt.xlabel('Time (in minutes)', fontsize=18, weight='bold')
    plt.legend(['Ransomware', 'Benign'] , loc='best', fontsize=14)
    plt.ylim(np.min(benign_unique_file_accessed['median'])-200, np.max(ransomware_unique_file_accessed['median'])+200)
    plt.yticks(fontsize=16)
    plt.show()
    
    # Saving the figure
    myFig.savefig('time_series_analysis/Results/Combined/Time_Series_Plot/Unique_Files_Accessed_Ransomware_vs_Benign.eps', format='eps', dpi=1200)
    myFig.savefig('time_series_analysis/Results/Combined/Time_Series_Plot/Unique_Files_Accessed_Ransomware_vs_Benign.png', format='png', dpi=150)
    
    # --- Time Series Plot of Entropy Feature (Ransomware vs Benign) ---
    plt.clf() # Clear figure
    myFig = plt.figure(figsize=[12,10])
    plt.plot(ransomware_entropy['median'], linestyle = 'dotted', marker = 'o', lw = 2, alpha=0.8, color = 'black')
    plt.plot(benign_entropy['median'], linestyle = 'dashed', marker = 's', lw = 2, alpha=0.8, color = 'black')
    plt.xticks(range(len(time_intervals)), time_intervals, fontsize=16)
    plt.fill_between([i for i in range(18)], ransomware_entropy['median'], benign_entropy['median'], color="grey", alpha="0.3")
    plt.title('Time Series Plot of Entropy Feature', fontsize=20, weight='bold')
    plt.ylabel('Median Counts', fontsize=18, weight='bold')
    plt.xlabel('Time (in minutes)', fontsize=18, weight='bold')
    plt.legend(['Ransomware', 'Benign'] , loc='best', fontsize=14)
    plt.yticks(fontsize=16)
    plt.show()
    
    # Saving the figure
    myFig.savefig('time_series_analysis/Results/Combined/Time_Series_Plot/Entropy_Feature_Ransomware_vs_Benign.eps', format='eps', dpi=1200)
    myFig.savefig('time_series_analysis/Results/Combined/Time_Series_Plot/Entropy_Feature_Ransomware_vs_Benign.png', format='png', dpi=150)
    
    # --- Time Series Plot of Buffer Length Feature (Ransomware vs Benign) ---
    plt.clf() # Clear figure
    myFig = plt.figure(figsize=[12,10])
    plt.plot(ransomware_buffer_length['median'], linestyle = 'dotted', marker = 'o', lw = 2, alpha=0.8, color = 'black')
    plt.plot(benign_buffer_length['median'], linestyle = 'dashed', marker = 's', lw = 2, alpha=0.8, color = 'black')
    plt.xticks(range(len(time_intervals)), time_intervals, fontsize=16)
    for ii in range(18):
        plt.text(ii-0.5, -700, format(int(ransomware_buffer_length['median'][ii]-benign_buffer_length['median'][ii]), ',d'), size=8.5, weight='bold')
    plt.fill_between([i for i in range(18)], ransomware_buffer_length['median'], benign_buffer_length['median'], color="grey", alpha="0.3")
    plt.title('Time Series Plot of Buffer Length Feature', fontsize=20, weight='bold')
    plt.ylabel('Median Counts', fontsize=18, weight='bold')
    plt.xlabel('Time (in minutes)', fontsize=18, weight='bold')
    plt.legend(['Ransomware', 'Benign'] , loc='best', fontsize=14)
    plt.ylim(-1000, np.max(ransomware_buffer_length['median'])+200)
    plt.yticks(fontsize=16)
    plt.show()
    
    # Saving the figure
    myFig.savefig('time_series_analysis/Results/Combined/Time_Series_Plot/Buffer_Length_Feature_Ransomware_vs_Benign.eps', format='eps', dpi=1200)
    myFig.savefig('time_series_analysis/Results/Combined/Time_Series_Plot/Buffer_Length_Feature_Ransomware_vs_Benign.png', format='png', dpi=150)


def generate_simple_box_plot(data, title, ylabel):
    ''' Generate a simple boxplot using mathplotlib
    where the data is a nested list. '''
    
    plt.clf() # Clear figure
    myFig = plt.figure(figsize=[12,10])
    plt.boxplot(data, vert=True, widths=0.8, patch_artist=True,
            boxprops=dict(facecolor='black', color='black'),
            capprops=dict(color='black'),
            whiskerprops=dict(color='black'),
            flierprops=dict(color='black', markeredgecolor='black'),
            medianprops=dict(color='white')
            )
    plt.xticks(range(1,19), [i * 5 for i in range(1,19)], fontsize=16)
    plt.title(str(title), fontsize=20, weight='bold')
    plt.xlabel('Time (in minutes)', fontsize=18, weight='bold')
    plt.ylabel(str(ylabel), fontsize=18, weight='bold')
    plt.yticks(fontsize=16)
    plt.show()
    
    # Saving the figure
    myFig.savefig('time_series_analysis/Results/' + str(title).replace(' ', '_')  + '.eps', format='eps', dpi=1200)
    myFig.savefig('time_series_analysis/Results/' + str(title).replace(' ', '_') + '.png', format='png', dpi=300)
    
    
def generate_simple_line_graph(X, Y, title, x_label, y_label):
    ''' Generate a simple line graph using mathplotlib
    where the data is given through X and Y along with lalbes and a title. '''
    
    plt.clf() # Clear figure
    myFig = plt.figure(figsize=[12,10])
    plt.plot(Y, linestyle = 'dotted', marker = 'o', lw = 2, alpha=0.8, color = 'black')
    plt.xticks(range(len(X)), X, fontsize=16)
    plt.title(str(title), fontsize=20, weight='bold')
    plt.ylabel(str(y_label), fontsize=18, weight='bold')
    plt.xlabel(str(x_label), fontsize=18, weight='bold')
    plt.yticks(fontsize=16)
    plt.show()
    
    # Saving the figure
    myFig.savefig('time_series_analysis/Results/' + str(title).replace(' ', '_')  + '.eps', format='eps', dpi=1200)
    myFig.savefig('time_series_analysis/Results/' + str(title).replace(' ', '_') + '.png', format='png', dpi=300)