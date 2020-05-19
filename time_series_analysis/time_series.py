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
from time_series_analysis.attribute_container import (IRP_Operations_Container, Flags_Container, File_System_Container)

if __name__ == '__main__':
    
    cwd = os.getcwd()   # Current project working direction
    dataset_names = [i for i in glob.glob(str(cwd) + '/Dataset/' + '*.gz')]
    dataset_names = sorted(dataset_names)
    
    dataset = pd.read_pickle(dataset_names[0], compression='gzip')
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
    
    print(ransomware_file_system_container.get_buffer_length())
    
    # Set different metrics from entropy
    benign_file_system_container.set_entropy(benign_instances['entropy'])
    ransomware_file_system_container.set_entropy(ransomware_instances['entropy'])
    
    
    
    
    
    