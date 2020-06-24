#!/usr/bin/env python3

__author__ = "Md. Ahsan Ayub"
__license__ = "GPL"
__credits__ = ["Ayub, Md. Ahsan", "Siraj, Ambareen"]
__maintainer__ = "Md. Ahsan Ayub"
__email__ = "mayub42@students.tntech.edu"
__status__ = "Prototype"


class IRP_Operations_Container(object):
    ''' A class to hold all the important pieces of details of each
    usuable IRP feature of the I/O Request Packet (IRP) log '''
    
    def __init__(self):
        '''Create an empty container '''
        self._operation_irp = 0  # Total number of IRP operations
        self._operation_fsf = 0  # Total number of FSF operations
        self._operation_fio = 0  # Total number of FIO operations
    
    def set_operation_irp(self, operation_irp: int):
        ''' Set the total number of IRP operations in a dataset '''
        self._operation_irp = operation_irp
    
    def get_operation_irp(self) -> int :
        ''' Get the value for IRP operations '''
        return self._operation_irp
    
    def set_operation_fsf(self, operation_fsf: int):
        ''' Set the total number of FSF operations in a dataset '''
        self._operation_fsf = operation_fsf
    
    def get_operation_fsf(self) -> int :
        ''' Get the value for FSF operations '''
        return self._operation_fsf
    
    def set_operation_fio(self, operation_fio: int):
        ''' Set the total number of FIO operations in a dataset '''
        self._operation_fio = operation_fio
    
    def get_operation_fio(self) -> int :
        ''' Get the value for FIO operations '''
        return self._operation_fio
    
    
class Flags_Container(object):
    ''' A class to hold all the important pieces of details of each
    usuable Flags-based feature of the I/O Request Packet (IRP) log '''
    
    def __init__(self):
        '''Create an empty container '''
        self._irp_flags = {}              # An empty dictonary
        self._major_operation_type = 0    # Store the unique count of the IRP major operation type
        self._minor_operation_type = 0    # Store the unique count of the IRP minor operation type
        self._status = 0                  # Store the unique count of the status
        self._transaction = 0             # Store the unique count of the transaction
    
    def set_irp_flags(self, irp_flags: dict):
        ''' Set the unique counts of the IRP flags in a dataset '''
        self._irp_flags['irp_flag'] = irp_flags['irp_flag']
        self._irp_flags['irp_nocache'] = irp_flags['irp_nocache']
        self._irp_flags['irp_paging_io'] = irp_flags['irp_paging_io']
        self._irp_flags['irp_synchoronous_api'] = irp_flags['irp_synchoronous_api']
        self._irp_flags['irp_synchoronous_paging_io'] = irp_flags['irp_synchoronous_paging_io']
    
    def get_irp_flags(self) -> dict :
        ''' Get the value for IRP flags '''
        return self._irp_flags
    
    def set_major_operation_type(self, major_operation_type: int):
        ''' Set the unique counts of the IRP major operation type in a dataset '''
        self._major_operation_type = major_operation_type
    
    def get_major_operation_type(self) -> int :
        ''' Get the value for IRP major operation type '''
        return self._major_operation_type
    
    def set_minor_operation_type(self, minor_operation_type: int):
        ''' Set the unique counts of the IRP minor operation type in a dataset '''
        self._minor_operation_type = minor_operation_type
    
    def get_minor_operation_type(self) -> int :
        ''' Get the value for IRP minor operation type '''
        return self._minor_operation_type
    
    def set_status(self, status: int):
        ''' Set the unique counts of the status in a dataset '''
        self._status = status
    
    def get_status(self) -> int :
        ''' Get the value for status '''
        return self._status
    
    def set_transaction(self, transaction: int):
        ''' Set the unique counts of the transaction in a dataset '''
        self._transaction = transaction
    
    def get_transaction(self) -> int :
        ''' Get the value for transaction '''
        return self._transaction
    
    
class File_System_Container(object):
    ''' A class to hold all the important pieces of details of each
    usuable file system based feature of the I/O Request Packet (IRP) log '''
    
    def __init__(self):
        '''Create an empty container '''
        self._file_object = 0
        self._file_accessed = 0
        self._buffer_length = {}
        self._entropy = {}
    
    def set_file_object(self, file_object: int):
        ''' Set the unique count of the file object in a dataset '''
        self._file_object = file_object
        
    def get_file_object(self) -> int :
        ''' Get the value for file object '''
        return self._file_object
    
    def set_file_accessed(self, file_accessed: int):
        ''' Set the unique count of the file accessed in a dataset '''
        self._file_accessed = file_accessed
        
    def get_file_accessed(self) -> int :
        ''' Get the value for file accessed '''
        return self._file_accessed
    
    def set_buffer_length(self, buffer_length: list):
        ''' Set the different counts of the buffer length in a dataset '''
        self._buffer_length['min_buffer_length'] = round(buffer_length.min())
        self._buffer_length['max_buffer_length'] = round(buffer_length.max())
        self._buffer_length['sum_buffer_length'] = round(buffer_length.sum())
        self._buffer_length['mean_buffer_length'] = round(buffer_length.mean())
        self._buffer_length['std_buffer_length'] = round(buffer_length.std())
    
    def get_buffer_length(self) -> dict :
        ''' Get the values for buffer length '''
        return self._buffer_length
    
    def set_entropy(self, entropy: list):
        ''' Set the different counts of the entrpy in a dataset '''
        self._entropy['min_entropy'] = entropy.min()
        self._entropy['max_entropy'] = entropy.max()
        self._entropy['sum_entropy'] = entropy.sum()
        self._entropy['mean_entropy'] = entropy.mean()
        self._entropy['std_entropy'] = entropy.std()
    
    def get_entropy(self) -> dict :
        ''' Get the values for entrpy '''
        return self._entropy