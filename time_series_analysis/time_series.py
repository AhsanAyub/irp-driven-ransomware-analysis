#!/usr/bin/env python3

__author__ = "Md. Ahsan Ayub"
__license__ = "GPL"
__credits__ = ["Ayub, Md. Ahsan", "Siraj, Ambareen"]
__maintainer__ = "Md. Ahsan Ayub"
__email__ = "mayub42@tntech.edu"
__status__ = "Prototype"

# Import libraries
import os
import glob
import pandas as pd

from attribute_container import (IRP_Operations_Container, Flags_Container, File_System_Container)
import time_series_analysis.time_series_visualization as visualiser
import helper as helper


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
                # Set FIO operations for both types of datasets
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
    

def combined_ransomware_analysis(master_container):
    ''' This method takes in a conainter (nested dictionary) where the keys are ransomware family
    name and its value is a dictionay containing another container of different objects '''
    
    ransomware_family_names = []
    
    # File System features for further analysis
    file_object = {}
    unique_file_accessed = {}
    entropy = {}
    buffer_length = {}
    
    # Flags features for further analysis
    irp_flags = {}
    irp_major_operation_type = {}
    irp_minor_operation_type = {}
    irp_status = {}
    
    # IRP operation feature for further analysis
    irp_operation = {}
    fsf_operation = {}
    fio_operation = {}
    
    for ransomware_family in master_container:
        # Temporary lists to populate the values for File System features
        temp_file_object = []
        temp_unique_file_accessed = []
        temp_entropy = []
        temp_buffer_length = []
        
        # Temporary lists to populate the values for Flags features
        temp_irp_flags = []
        temp_irp_major_operation_type = []
        temp_irp_minor_operation_type = []
        temp_irp_status = []
        
        # Temporary lists to populate the values for Flags features
        temp_irp_operation = []
        temp_fsf_operation = []
        temp_fio_operation = []
        
        # Iterate through the master container to populate the dictionaries
        for key in master_container[ransomware_family]:
            for objects in master_container[ransomware_family][key]['ransomware']:
                if isinstance(objects, File_System_Container): # Needed for file system features
                    temp_file_object.append(objects.get_file_object())
                    temp_unique_file_accessed.append(objects.get_file_accessed())
                    temp_buffer_length.append(objects.get_buffer_length()['mean_buffer_length'])
                    temp_entropy.append(objects.get_entropy()['mean_entropy'])
                    
                elif isinstance(objects, Flags_Container): # Needed for flags based features
                    temp_irp_flags.append(objects.get_irp_flags()['irp_flag'])
                    temp_irp_major_operation_type.append(objects.get_major_operation_type())
                    temp_irp_minor_operation_type.append(objects.get_minor_operation_type())
                    temp_irp_status.append(objects.get_status())

                elif isinstance(objects, IRP_Operations_Container): # Needed for irp operation feature          
                    temp_irp_operation.append(objects.get_operation_irp())
                    temp_fsf_operation.append(objects.get_operation_fsf())
                    temp_fio_operation.append(objects.get_operation_fio())
                    
                else: # Highly unlikely this will occur
                    pass
        
        ransomware_family_names.append(str(ransomware_family))  # This list will contain the list of families
        
        ''' Populate dictionaries where the keys are ransoware family names '''
        # File system feature space
        file_object[str(ransomware_family)] = temp_file_object
        unique_file_accessed[str(ransomware_family)] = temp_unique_file_accessed
        entropy[str(ransomware_family)] = temp_entropy
        buffer_length[str(ransomware_family)] = temp_buffer_length
        
        # Flag-based feature space
        irp_flags[str(ransomware_family)] = temp_irp_flags
        irp_major_operation_type[str(ransomware_family)] = temp_irp_major_operation_type
        irp_minor_operation_type[str(ransomware_family)] = temp_irp_minor_operation_type
        irp_status[str(ransomware_family)] = temp_irp_status
        
        # IRP Operation based feature space
        irp_operation[str(ransomware_family)] = temp_irp_operation
        fsf_operation[str(ransomware_family)] = temp_fsf_operation
        fio_operation[str(ransomware_family)] = temp_fio_operation
    
    ''' A code snippet that used to generate the data distribution csv
    for i in range(18):
        temp = []
        for ransomware_family_name in ransomware_family_names:
            try:
                temp.append(fio_operation[ransomware_family_name][i])
            except:
                pass
        print(np.mean(temp)) '''
    
    # --- Generate IRP Major Operation Type feature in box plot graph ---
    data = []
    for i in range(18):
        temp = []
        for ransomware_family_name in ransomware_family_names:
            try:
                temp.append(irp_minor_operation_type[ransomware_family_name][i])
            except:
                continue
        data.append(temp)
    visualiser.generate_simple_box_plot(data, "IRP Minor Operation Type Feature Distribution\namong Ransomware Families", "Unique Counts")
    
    # --- Generate file object feature in box plot graph ---
    data = []    
    for i in range(18):
        temp = []
        for ransomware_family_name in ransomware_family_names:
            try:
                temp.append(file_object[ransomware_family_name][i])
            except:
                continue
        data.append(temp)
    visualiser.generate_simple_box_plot(data, "File Object Feature Distribution among Ransomware Families", "Unique Counts")
    
    # --- Generate file accessed feature in box plot graph ---
    data = []    
    for i in range(18):
        temp = []
        for ransomware_family_name in ransomware_family_names:
            try:
                temp.append(unique_file_accessed[ransomware_family_name][i])
            except:
                continue
        data.append(temp)
    visualiser.generate_simple_box_plot(data, "Number of Files Accessed by Ransomware Families", "Unique Counts")
    
    # --- Generate entropy feature in box plot graph ---
    data = []    
    for i in range(18):
        temp = []
        for ransomware_family_name in ransomware_family_names:
            try:
                temp.append(entropy[ransomware_family_name][i])
            except:
                continue
        data.append(temp)
    visualiser.generate_simple_box_plot(data, "Entropy Feature Distribution among Ransomware Families", "Mean Values")
    
    # --- Generate buffer length feature in box plot graph ---
    data = []    
    for i in range(18):
        temp = []
        for ransomware_family_name in ransomware_family_names:
            try:
                temp.append(buffer_length[ransomware_family_name][i])
            except:
                continue
        data.append(temp)
    visualiser.generate_simple_box_plot(data, "Buffer Length Feature Distribution among Ransomware Families", "Mean Values")
    
    # --- Generate IRP Major Operation Type feature in box plot graph ---
    data = []
    for i in range(18):
        temp = []
        for ransomware_family_name in ransomware_family_names:
            try:
                temp.append(irp_major_operation_type[ransomware_family_name][i])
            except:
                continue
        data.append(temp)
    visualiser.generate_simple_box_plot(data, "IRP Major Operation Type Feature Distribution\namong Ransomware Families", "Unique Counts")
    
    # --- Generate IRP Minor Operation Type feature in box plot graph ---
    data = []
    for i in range(18):
        temp = []
        for ransomware_family_name in ransomware_family_names:
            try:
                temp.append(irp_minor_operation_type[ransomware_family_name][i])
            except:
                continue
        data.append(temp)
    visualiser.generate_simple_box_plot(data, "IRP Minor Operation Type Feature Distribution\namong Ransomware Families", "Unique Counts")
    
    # --- Generate IRP flags feature in box plot graph ---
    data = []
    for i in range(18):
        temp = []
        for ransomware_family_name in ransomware_family_names:
            try:
                temp.append(irp_flags[ransomware_family_name][i])
            except:
                continue
        data.append(temp)
    visualiser.generate_simple_box_plot(data, "IRP Flags Feature Distribution among Ransomware Families", "Unique Counts")
    
    # --- Generate IRP status feature in box plot graph ---
    data = []
    for i in range(18):
        temp = []
        for ransomware_family_name in ransomware_family_names:
            try:
                temp.append(irp_status[ransomware_family_name][i])
            except:
                continue
        data.append(temp)
    visualiser.generate_simple_box_plot(data, "IRP Status Feature Distribution among Ransomware Families", "Unique Counts")
    
    # --- Generate IRP Operation Type feature in box plot graph ---
    data = []
    for i in range(18):
        temp = []
        for ransomware_family_name in ransomware_family_names:
            try:
                temp.append(irp_operation[ransomware_family_name][i])
            except:
                continue
        data.append(temp)
    visualiser.generate_simple_box_plot(data, "IRP Operation Feature Distribution among Ransomware Families", "Unique Counts")
    
    # --- Generate FSF Operation Type feature in box plot graph ---
    data = []
    for i in range(18):
        temp = []
        for ransomware_family_name in ransomware_family_names:
            try:
                temp.append(fsf_operation[ransomware_family_name][i])
            except:
                continue
        data.append(temp)
    visualiser.generate_simple_box_plot(data, "FSF Operation Feature Distribution among Ransomware Families", "Unique Counts")   
    
    # --- Generate FIO Operation Type feature in box plot graph ---
    data = []
    for i in range(18):
        temp = []
        for ransomware_family_name in ransomware_family_names:
            try:
                temp.append(fio_operation[ransomware_family_name][i])
            except:
                continue
        data.append(temp)
    visualiser.generate_simple_box_plot(data, "FIO Operation Feature Distribution among Ransomware Families", "Unique Counts")   
    
    '''This is a static code written to generate the time series trend graphs for certain features
    saved in a CSV file. The features values are means from all the combined ransoware families. 
    
    dataset = pd.read_csv(str(cwd) + '/time_series_analysis/Results/Combined/ransomware_combined_dump_feature_distribution.csv')
   
    visualiser.generate_simple_line_graph(dataset['Time'].tolist(), dataset['IRP Operation'].tolist(),
                               "Ransomware IRP Operation Feature Trend", "Time", "Mean Counts")
    
    visualiser.generate_simple_line_graph(dataset['Time'].tolist(), dataset['FSF Operation'].tolist(),
                               "Ransomware FSF Operation Feature Trend", "Time", "Mean Counts")
    
    visualiser.generate_simple_line_graph(dataset['Time'].tolist(), dataset['FIO Operation'].tolist(),
                               "Ransomware FIO Operation Feature Trend", "Time", "Mean Counts")
   
    visualiser.generate_simple_line_graph(dataset['Time'].tolist(), dataset['IRP Flags'].tolist(),
                               "Ransomware IRP Flags Feature Trend", "Time", "Mean Unique Counts")
   
    visualiser.generate_simple_line_graph(dataset['Time'].tolist(), dataset['IRP Status'].tolist(),
                               "Ransomware IRP Status Feature Trend", "Time", "Mean Unique Counts")
   
    visualiser.generate_simple_line_graph(dataset['Time'].tolist(), dataset['File Object'].tolist(),
                               "Ransomware File Object Feature Trend", "Time", "Mean Unique Counts")
   
    visualiser.generate_simple_line_graph(dataset['Time'].tolist(), dataset['File Accesed'].tolist(),
                               "Ransomware Unique File Accessed Trend", "Time", "Mean Counts")
        
    visualiser.generate_simple_line_graph(dataset['Time'].tolist(), dataset['Buffer Length'].tolist(),
                               "Ransomware Buffer Length Feature Trend", "Time", "Mean Counts") 
    
    visualiser.generate_simple_line_graph(dataset['Time'].tolist(), dataset['Entropy'].tolist(),
                               "Ransomware Entrpy Feature Trend", "Time", "Mean Counts") '''

                                          
    # Delete the variables
    #del temp, data, dataset


if __name__ == '__main__':
    
    cwd = os.getcwd()   # Current project working direction
    
    # Get the feature containers of all the 5 mins time chunk datasets
    '''containers = build_attribute_containers([i for i in glob.glob(str(cwd) + '/Dataset/TeslaCrypt/' + '*.gz')])

    visualiser.self_irp_operations_analysis(containers, "TeslaCrypt")
    visualiser.self_irp_flags_analysis(containers, "TeslaCrypt")
    visualiser.self_file_system_analysis(containers, "TeslaCrypt")
    
    file_system_container = build_process_wise_file_system_container([i for i in glob.glob(str(cwd) + '/Dataset/TeslaCrypt/' + '*.gz')])
    visualiser.comparitive_file_system_analysis_individual_family(file_system_container, "TeslaCrypt")'''
    
    # Get all the ransomware family datasets' paths from helper
    ransomware_family_name_paths = helper.get_all_ransomsomware_dataset_file_paths()
    
    # Master container is going to be built through this loop
    master_container = {}
    for ransomware_family_name_path in ransomware_family_name_paths:
        master_container[str(ransomware_family_name_path).split('/')[-1]] = build_attribute_containers([i for i in glob.glob(str(ransomware_family_name_path) + '/*.gz')])

    # Perform the time series analysis for combined ransomware families dataset
    combined_ransomware_analysis(master_container)
    
    # Perform the time series analsis for combined ransomware and its benign observations
    visualiser.combined_file_system_feature_distribution_ransomware_and_benign(master_container)
    
    # Free memory
    del ransomware_family_name_paths, ransomware_family_name_path, master_container, containers, file_system_container