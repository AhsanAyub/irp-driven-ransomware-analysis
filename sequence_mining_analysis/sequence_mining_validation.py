#!/usr/bin/env python3

__author__ = "Md. Ahsan Ayub"
__license__ = "GPL"
__credits__ = ["Ayub, Md. Ahsan", "Siraj, Ambareen"]
__maintainer__ = "Md. Ahsan Ayub"
__email__ = "mayub42@students.tntech.edu"
__status__ = "Prototype"

# Import libraries
import pandas as pd
import matplotlib.pyplot as plt
import helper as helper
import sequence_mining_analysis.sequence_mining as sequence_mining


def generate_sequence_dict_from_sequence_list(sequence_list):
    ''' The method will take on the sequence list and then create a dictionary
    from the list. The list is a nested list where the number of columns are
    the number of the ransomnware families. '''
    
    ransomware_test_family_names = [str(item).split('/')[-1] for item in helper.get_all_ransomsomware_family_paths()]
    sequence_dict = {}
    for ransomware_test_family_name in ransomware_test_family_names:
        sequence_dict[str(ransomware_test_family_name)] = []
        
    for i in range(len(sequence_list)):
        for j in range(len(sequence_list[i])):
            sequence_dict[str(ransomware_test_family_names[j])].append(sequence_list[i][j])
            
    return sequence_dict


# Driver program
if __name__ == '__main__':
    # Get the IRP Major Operation Type container for test set
    irp_major_operation_type_pattern_count_container = sequence_mining.generate_irp_major_operation_type_pattern_count(helper.get_all_ransomsomware_family_paths())
    
    # Obtain sequences list for further analysis
    bc_sequence, bcC_sequence, bcG_sequence, EGbc_sequence, EGbcC_sequence = sequence_mining.get_ransomware_process_sequence_counts(irp_major_operation_type_pattern_count_container)
    
    # Delete the contianer
    del irp_major_operation_type_pattern_count_container
     
    # Convert the lists to its dictionary for ransomware family specific analysis
    bc_sequence_dict = generate_sequence_dict_from_sequence_list(bc_sequence)
    bcC_sequence_dict = generate_sequence_dict_from_sequence_list(bcC_sequence)
    bcG_sequence_dict = generate_sequence_dict_from_sequence_list(bcG_sequence)
    EGbc_sequence_dict = generate_sequence_dict_from_sequence_list(EGbc_sequence)
    EGbcC_sequence_dict = generate_sequence_dict_from_sequence_list(EGbcC_sequence)
    
    # Delete the lists
    del (bc_sequence, bcC_sequence, bcG_sequence, EGbc_sequence, EGbcC_sequence)
    
    # Generate the dataframe from dictionary
    ransomware_family_names = []
    for key in bc_sequence_dict:
        print(ransomware_family_names.append(key))
        
    data = {'bc': [],
            'bcC': [],
            'bcG': [],
            'EGbc': [],
            'EGbcC': [],
            'family_name': []}
    
    for family_name in ransomware_family_names:
        for i in range(6):
            data['bc'].append(bc_sequence_dict[family_name][i])
            data['bcC'].append(bcC_sequence_dict[family_name][i])
            data['bcG'].append(bcG_sequence_dict[family_name][i])
            data['EGbc'].append(EGbc_sequence_dict[family_name][i])
            data['EGbcC'].append(EGbcC_sequence_dict[family_name][i])
            data['family_name'].append(family_name)
            
    data = pd.DataFrame(data)
    print(data.head())
    
    # Performing cluster algorithms
    from sklearn.decomposition import PCA
    from sklearn.preprocessing import StandardScaler 
    from sklearn import preprocessing
    import numpy as np
    import seaborn as sn
    
    X = data.iloc[:,0:3].values
    Y = data.iloc[:, -1]
    le = preprocessing.LabelEncoder()
    Y = le.fit_transform(Y)
    
    pca = PCA(n_components=2)
    pca_data = pca.fit(StandardScaler().fit_transform(X)).transform(StandardScaler().fit_transform(X))
    
    # Attaching the labels for each 2D data point
    pca_data = np.vstack((pca_data.T, Y)).T
    pca_df = pd.DataFrame(data=pca_data, columns=("PCA-1", "PCA-2", "Ransomware Family ID"))
    
    plt.clf() # Clear figure
    myFig = plt.figure(figsize=[12,10])
    myFig = sn.set_context("notebook")
    myFig = sn.axes_style("whitegrid")
    myFig = sn.FacetGrid(pca_df,hue="Ransomware Family ID", size=6).map(plt.scatter, "PCA-1", "PCA-2").add_legend()
    plt.title('Sequence Counts of #1, #2, and #3 with PCA', fontsize=20, weight='bold')
    plt.ylabel('PCA-2', fontsize=18, weight='bold')
    plt.xlabel('PCA-1', fontsize=18, weight='bold')
    plt.yticks(fontsize=16)
    plt.show()
    
    myFig.savefig('sequence_mining_analysis/Results/sequence_counts_pca_1_2_3.png', format='png', dpi=150)
    
    ''' The following is the dataset of all five sequences based on the emprical analysis, that
    is, the box plot analysis of the training ransomware family set and from the dataset,
    we will consider some threshold values. '''
    
    dataset = pd.read_csv('./sequence_mining_analysis/Results/irp_mj_opn_type_sequences_box_plot_analysis.csv')
    print(dataset.head())
    for cols in dataset.columns: dataset[cols] = dataset[cols].astype(float)
    
    ''' Generate line graph for b->c sequnce comparison chart with threshold boundary '''
    time_intervals = [i * 5 for i in range(1,19)]
    plt.clf() # Clear figure
    myFig = plt.figure(figsize=[12,10])
    plt.plot(dataset['q1_bc_sequence'], linestyle = 'dotted', lw = 2, alpha=0.4, color = 'black')
    plt.plot(dataset['q3_bc_sequence'], linestyle = 'dashed', lw = 2, alpha=0.4, color = 'black')
    for family_name in bc_sequence_dict:
        for i in range(18):
            if(bc_sequence_dict[str(family_name)][i] >= (dataset['q1_bc_sequence'][i] + dataset['min_bc_sequence'][i]) / 2):
                plt.scatter(i, bc_sequence_dict[str(family_name)][i], marker = 'D', linewidths = 1.5, alpha=0.5, c = 'black', edgecolors= 'black')
            else:
                plt.scatter(i, bc_sequence_dict[str(family_name)][i], marker = 'x', linewidths = 1.5, alpha=0.8, c = 'red', edgecolors= 'black')
                print(str(i), str(family_name), bc_sequence_dict[str(family_name)][i])
    plt.xticks(range(len(time_intervals)), time_intervals, fontsize=16)
    plt.title('Time Series Plot for Sequence #1 Validation', fontsize=20, weight='bold')
    plt.ylabel('Unique Counts', fontsize=18, weight='bold')
    plt.xlabel('Time (in minutes)', fontsize=18, weight='bold')
    plt.legend(['Q1 Median Values', 'Q3 Median Values'] , loc='best', fontsize=14)
    plt.yticks(fontsize=16)
    plt.show()
    
    ''' Generate line graph for b->c->C sequnce comparison chart with threshold boundary '''
    plt.clf() # Clear figure
    myFig = plt.figure(figsize=[12,10])
    plt.plot(dataset['q1_bcC_sequence'], linestyle = 'dotted', lw = 2, alpha=0.4, color = 'black')
    plt.plot(dataset['q3_bcC_sequence'], linestyle = 'dashed', lw = 2, alpha=0.4, color = 'black')
    for family_name in bcC_sequence_dict:
        #plt.scatter([i * 1 for i in range(18)], bc_sequence_dict[str(family_name)], marker = 'x', linewidths = 1.5, alpha=0.7, c = 'black', edgecolors= 'black')
        for i in range(18):
            if(bcC_sequence_dict[str(family_name)][i] >= (dataset['q1_bcC_sequence'][i] + dataset['min_bcC_sequence'][i]) / 2):
                plt.scatter(i, bcC_sequence_dict[str(family_name)][i], marker = 'D', linewidths = 1.5, alpha=0.5, c = 'black', edgecolors= 'black')
            else:
                plt.scatter(i, bcC_sequence_dict[str(family_name)][i], marker = 'x', linewidths = 1.5, alpha=0.8, c = 'red', edgecolors= 'black')
                print(str(i), str(family_name), bcC_sequence_dict[str(family_name)][i])
    plt.xticks(range(len(time_intervals)), time_intervals, fontsize=16)
    plt.title('Time Series Plot for Sequence #2 Validation', fontsize=20, weight='bold')
    plt.ylabel('Unique Counts', fontsize=18, weight='bold')
    plt.xlabel('Time (in minutes)', fontsize=18, weight='bold')
    plt.legend(['Q1 Median Values', 'Q3 Median Values'] , loc='best', fontsize=14)
    plt.yticks(fontsize=16)
    plt.show()
    
    ''' Generate line graph for b->c->G sequnce comparison chart with threshold boundary '''
    plt.clf() # Clear figure
    myFig = plt.figure(figsize=[12,10])
    plt.plot(dataset['q1_bcG_sequence'], linestyle = 'dotted', lw = 2, alpha=0.4, color = 'black')
    plt.plot(dataset['q3_bcG_sequence'], linestyle = 'dashed', lw = 2, alpha=0.4, color = 'black')
    for family_name in bcG_sequence_dict:
        #plt.scatter([i * 1 for i in range(18)], bc_sequence_dict[str(family_name)], marker = 'x', linewidths = 1.5, alpha=0.7, c = 'black', edgecolors= 'black')
        for i in range(18):
            if(bcG_sequence_dict[str(family_name)][i] >= (dataset['q1_bcG_sequence'][i] + dataset['min_bcG_sequence'][i]) / 2):
                plt.scatter(i, bcG_sequence_dict[str(family_name)][i], marker = 'D', linewidths = 1.5, alpha=0.5, c = 'black', edgecolors= 'black')
            else:
                plt.scatter(i, bcG_sequence_dict[str(family_name)][i], marker = 'x', linewidths = 1.5, alpha=0.8, c = 'red', edgecolors= 'black')
                print(str(i), str(family_name), bcG_sequence_dict[str(family_name)][i], str((dataset['q1_bcG_sequence'][i] + dataset['min_bcG_sequence'][i]) / 2))
    plt.xticks(range(len(time_intervals)), time_intervals, fontsize=16)
    plt.title('Time Series Plot for Sequence #3 Validation', fontsize=20, weight='bold')
    plt.ylabel('Unique Counts', fontsize=18, weight='bold')
    plt.xlabel('Time (in minutes)', fontsize=18, weight='bold')
    plt.legend(['Q1 Median Values', 'Q3 Median Values'] , loc='best', fontsize=14)
    plt.yticks(fontsize=16)
    plt.show()