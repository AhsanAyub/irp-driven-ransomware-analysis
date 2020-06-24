#!/usr/bin/env python3

__author__ = "Md. Ahsan Ayub"
__license__ = "GPL"
__credits__ = ["Ayub, Md. Ahsan", "Siraj, Ambareen"]
__maintainer__ = "Md. Ahsan Ayub"
__email__ = "mayub42@students.tntech.edu"
__status__ = "Prototype"

# Import libraries
import pandas as pd
import numpy as np
import re
import matplotlib.pyplot as plt

import helper as helper
import sequence_mining_analysis.IRP_Code_Definations as definations
import time_series_analysis.time_series_visualization as visualiser

def generate_irp_major_operation_type_pattern_count():
    ''' This utility method will scan through all the ransomware family datasets
    and then measure the counts of 5 pre-defined patterns / sequences counts
    appeared in the datasets. The method will return the counts in a dictionary. '''
    
    irp_major_operation_type_pattern_count_container = {}
    ransomsomware_family_paths = helper.get_all_ransomsomware_family_paths()
    for ransomsomware_family_path in ransomsomware_family_paths:
        ransomware_family_name = ransomsomware_family_path.split('/')[-1]
        ransomware_family_dataset_paths = helper.get_ransomsomware_family_datasete_paths(ransomsomware_family_path)
        ransomware_family_dataset_paths = ransomware_family_dataset_paths
        temp = {}
        i = 1
        for ransomware_family_dataset_path in ransomware_family_dataset_paths:
            dataset = pd.read_pickle(ransomware_family_dataset_path, compression='gzip')
            dataset = dataset.drop(dataset[(dataset['class'] != 1)].index) # ransomware instances
            process_names = dataset['process_name'].unique().tolist()
            
            ''' With manual exploration by Suffix Tree, we observe 5 patterns from the feature
            IRP Major Operation Type. '''
            counts = {} # The dictionary to store counts
            counts["b->c"] = 0    # Pattern 1
            counts["b->c->C"] = 0    # Pattern 2
            counts["b->c->G"] = 0    # Pattern 3
            counts["E->G->b->c"] = 0    # Pattern 4
            counts["E->(G->b->c)->C"] = 0    # Pattern 5
            
            for process_name in process_names:
                sample = dataset.drop(dataset[(dataset['process_name'] != process_name)].index)
                irp_major_operation_type = sample.major_operation_type
                irp_major_operation_type.replace('', np.NaN)
                irp_major_operation_type.dropna()
                irp_major_operation_type = irp_major_operation_type.map(definations.irp_major_operation).tolist()
                irp_major_operation_type = ''.join([str(item) for item in irp_major_operation_type])
                
                counts["b->c"] += len(re.findall(r"bc", irp_major_operation_type))
                counts["b->c->C"] += len(re.findall(r"bcC", irp_major_operation_type))
                counts["b->c->G"] += len(re.findall(r"bcG", irp_major_operation_type))
                counts["E->G->b->c"] += len(re.findall(r"EGbc", irp_major_operation_type))
                counts["E->(G->b->c)->C"] += len(re.findall(r"E(Gbc)+C", irp_major_operation_type))
            
            temp[str(i*5)] = counts
            i += 1
        irp_major_operation_type_pattern_count_container[str(ransomware_family_name)] = temp
    return irp_major_operation_type_pattern_count_container


# Driver program
if __name__ == '__main__':
    # Get the IRP Major Operation Type container for futher analysis
    irp_major_operation_type_pattern_count_container = generate_irp_major_operation_type_pattern_count()
    
    # Sequences list to plot different graphical illustrations
    bc_sequence = []
    bcC_sequence = []
    bcG_sequence = []
    EGbc_sequence = []
    EGbcC_sequence = []
    
    ''' Populate all the sequences' lists respective to time; hence it will be a nested
    list. The first row will indicate the time at 5 min, the follwing is 10 min, and so on. '''
    ransomware_family_names = [family_name.split('/')[-1] for family_name in helper.get_all_ransomsomware_family_paths()]
    time_intervals = [i * 5 for i in range(1,19)]
    for time in time_intervals:
        # Temp lists to populate its main lists
        temp_bc_sequence = []
        temp_bcC_sequence = []
        temp_bcG_sequence = []
        temp_EGbc_sequence = []
        temp_EGbcC_sequence = []
        for ransomware_family_name in ransomware_family_names:
            try:
                temp_bc_sequence.append(irp_major_operation_type_pattern_count_container[ransomware_family_name][str(time)]['b->c'])
                temp_bcC_sequence.append(irp_major_operation_type_pattern_count_container[ransomware_family_name][str(time)]['b->c->C'])
                temp_bcG_sequence.append(irp_major_operation_type_pattern_count_container[ransomware_family_name][str(time)]['b->c->G'])
                temp_EGbc_sequence.append(irp_major_operation_type_pattern_count_container[ransomware_family_name][str(time)]['E->G->b->c'])
                temp_EGbcC_sequence.append(irp_major_operation_type_pattern_count_container[ransomware_family_name][str(time)]['E->(G->b->c)->C'])
            except:
                continue
        
        # Populate to its main lists
        bc_sequence.append(temp_bc_sequence)
        bcC_sequence.append(temp_bcC_sequence)
        bcG_sequence.append(temp_bcG_sequence)
        EGbc_sequence.append(temp_EGbc_sequence)
        EGbcC_sequence.append(temp_EGbcC_sequence)
    
    # Delete temp variables
    del (temp_bc_sequence, temp_bcC_sequence, temp_bcG_sequence, temp_EGbc_sequence, temp_EGbcC_sequence, time, ransomware_family_name)
    
    ''' Generate box plot for all the sequences by utilizing time series visualization script '''
    visualiser.generate_simple_box_plot(bc_sequence, "Sequence #1 distribution among Ransomware Families", "Unique Counts")
    visualiser.generate_simple_box_plot(bcC_sequence, "Sequence #2 distribution among Ransomware Families", "Unique Counts")
    visualiser.generate_simple_box_plot(bcG_sequence, "Sequence #3 distribution among Ransomware Families", "Unique Counts")                                        
    visualiser.generate_simple_box_plot(EGbc_sequence, "Sequence #4 distribution among Ransomware Families", "Unique Counts")                                        
    visualiser.generate_simple_box_plot(EGbcC_sequence, "Sequence #5 distribution among Ransomware Families", "Unique Counts")                                        
                                        
    ''' Generate line graph containing all the sequences' median values '''
    # All the five sequences
    plt.clf() # Clear figure
    myFig = plt.figure(figsize=[12,10])
    plt.plot([np.median(i) for i in bc_sequence], linestyle = 'solid', marker = 'v', lw = 2, alpha=0.8, color = 'black')
    plt.plot([np.median(i) for i in bcC_sequence], linestyle = 'dotted', marker = 'p', lw = 2, alpha=0.8, color = 'black')
    plt.plot([np.median(i) for i in bcG_sequence], linestyle = 'dashed', marker = 's', lw = 2, alpha=0.8, color = 'black')
    plt.plot([np.median(i) for i in EGbc_sequence], linestyle = 'dashdot', marker = 'o', lw = 2, alpha=0.8, color = 'black')
    plt.plot([np.median(i) for i in EGbcC_sequence], linestyle = 'solid', marker = 'x', lw = 2, alpha=0.8, color = 'black')
    plt.xticks(range(len(time_intervals)), time_intervals, fontsize=16)
    plt.title('Time Series Plot for IRP Major Operation Type\'s Sequences', fontsize=20, weight='bold')
    plt.ylabel('Unique Counts (Median)', fontsize=18, weight='bold')
    plt.xlabel('Time (in minutes)', fontsize=18, weight='bold')
    plt.legend(['Sequence #1', 'Sequence #2', 'Sequence #3', 'Sequence #4', 'Sequence #5'] , loc='best', fontsize=14)
    plt.yticks(fontsize=16)
    plt.show()
    
    # Saving the figure
    myFig.savefig('sequence_mining_analysis/Results/Time_Series_Plot_IRP_Major_Operation_Type_Sequences.eps', format='eps', dpi=1200)
    myFig.savefig('sequence_mining_analysis/Results/Time_Series_Plot_IRP_Major_Operation_Type_Sequences.png', format='png', dpi=150)
    
    # Three majors sequences
    plt.clf() # Clear figure
    myFig = plt.figure(figsize=[12,10])
    plt.plot([np.median(i) for i in bc_sequence], linestyle = 'solid', marker = 'v', lw = 2, alpha=0.8, color = 'black')
    plt.plot([np.median(i) for i in bcC_sequence], linestyle = 'dotted', marker = 'p', lw = 2, alpha=0.8, color = 'black')
    plt.plot([np.median(i) for i in bcG_sequence], linestyle = 'dashed', marker = 's', lw = 2, alpha=0.8, color = 'black')
    plt.xticks(range(len(time_intervals)), time_intervals, fontsize=16)
    plt.title('Time Series Plot for IRP Major Operation Type\'s Sequences', fontsize=20, weight='bold')
    plt.ylabel('Unique Counts (Median)', fontsize=18, weight='bold')
    plt.xlabel('Time (in minutes)', fontsize=18, weight='bold')
    plt.legend(['Sequence #1', 'Sequence #2', 'Sequence #3'] , loc='best', fontsize=14)
    plt.yticks(fontsize=16)
    plt.show()
    
    # Saving the figure
    myFig.savefig('sequence_mining_analysis/Results/Time_Series_Plot_IRP_Major_Operation_Type_Major_Three_Sequences.eps', format='eps', dpi=1200)
    myFig.savefig('sequence_mining_analysis/Results/Time_Series_Plot_IRP_Major_Operation_Type_Major_Three_Sequences.png', format='png', dpi=150)