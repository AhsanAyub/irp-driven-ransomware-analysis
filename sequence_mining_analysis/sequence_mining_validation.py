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
import seaborn as sn
import matplotlib.pyplot as plt
import matplotlib.font_manager

import helper as helper
import sequence_mining_analysis.sequence_mining as sequence_mining

# Libraries required to perform cluster algorithms
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler 
from sklearn import preprocessing


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


def explore_cluster_in_pattern_counts(data):
    ''' With the five patterns' counts, this method explores a single cluster with PCA to solidify the belief
    that the ransomware families will show similar behavior, i.e., data points in the same region. '''

    X = data.iloc[:,:-1].values
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
    plt.title('Sequence Counts with PCA', fontsize=20, weight='bold')
    plt.ylabel('PCA-2', fontsize=18, weight='bold')
    plt.xlabel('PCA-1', fontsize=18, weight='bold')
    plt.yticks(fontsize=16)
    plt.show()
    
    myFig.savefig('sequence_mining_analysis/Results/sequence_counts_pca_all.png', format='png', dpi=150)
    myFig.savefig('sequence_mining_analysis/Results/sequence_counts_pca_all.eps', format='eps', dpi=1200)
    

def perform_one_class_svm_novelty_detection(data):
    ''' With the five patterns' counts, this method performs One-Class SVM with non-linear kernel (RBF) for novelty detection
    It is an unsupervised algorithm that learns a decision function for novelty detection: classifying
    new data as similar or different to the training set.
    
    The experimentation is performed with different time chunks and number of sequences. '''
    
    # Importing necessary libraries
    from sklearn import svm
    from sklearn.model_selection import train_test_split
    
    # Performing PCA
    X = data.iloc[:,0:4].values
    pca = PCA(n_components=2)
    X = pca.fit(StandardScaler().fit_transform(X)).transform(StandardScaler().fit_transform(X))
    
    # Spliting the observations into 75% training and 25% testing
    X_train, X_test = train_test_split(X, test_size=0.25, random_state=42)
    
    # One-Class SVM classifier intialization and generate results
    classifier = svm.OneClassSVM(nu=0.1, kernel="rbf", gamma=0.1)
    classifier.fit(X_train)
    Y_pred_train = classifier.predict(X_train)
    Y_pred_test = classifier.predict(X_test)
    n_error_train = Y_pred_train[Y_pred_train == -1].size
    n_error_test = Y_pred_test[Y_pred_test == -1].size
    error_train = n_error_train / Y_pred_train.shape[0] * 100
    error_novel = n_error_test / Y_pred_test.shape[0] * 100
    
    # Visualization
    plt.clf()
    myFig = plt.figure(figsize=[10,8])
    xx, yy = np.meshgrid(np.linspace(-5, 10, 500), np.linspace(-5, 9, 500))
    Z = classifier.decision_function(np.c_[xx.ravel(), yy.ravel()])
    Z = Z.reshape(xx.shape)
    plt.contourf(xx, yy, Z, levels=np.linspace(Z.min(), 0, 7), cmap=plt.cm.PuBu)
    a = plt.contour(xx, yy, Z, levels=[0], linewidths=2, colors='darkred')
    plt.contourf(xx, yy, Z, levels=[0, Z.max()], colors='palevioletred')
    s = 60
    b1 = plt.scatter(X_train[:, 0], X_train[:, 1], c='white', s=s, edgecolors='k')
    b2 = plt.scatter(X_test[:, 0], X_test[:, 1], c='gold', s=s, edgecolors='k')
    plt.axis('tight')
    plt.legend([a.collections[0], b1, b2],
               ["Learned Frontier", "Training Observations", "New Regular Observations"], loc="best",
               prop=matplotlib.font_manager.FontProperties(size=14))
    plt.xlabel("Error Train: %.2f%% and Error Novel Regular: %.2f%%" % (error_train, error_novel), fontsize=13, weight="bold")
    plt.yticks(fontsize=14)
    plt.xticks(fontsize=14)
    plt.title('Novelty Detection using OneClass SVM of Ransomware Families\'\nSequence #1, #2, #3, and #4 Counts from 40 minutes of IRP Logs', fontsize=14, weight='bold')
    plt.show()
    
    # Save figure
    myFig.savefig('sequence_mining_analysis/Results/novelty_detection/One-Class_SVM/40_mins_sequences_1_2_3_4.png', format='png', dpi=150)
    myFig.savefig('sequence_mining_analysis/Results/novelty_detection/One-Class_SVM/40_mins_sequences_1_2_3_4.eps', format='eps', dpi=1200)


def perform_isolation_forest_novelty_detection(data):
    ''' With the five patterns' counts, this method performs Isolation Forest that ‘isolates’ observations by
    randomly selecting a feature and then randomly selecting a split value between the maximum and minimum values of
    the selected feature.
    
    The experimentation is performed with different time chunks and number of sequences. '''
    
    # Importing necessary libraries
    from sklearn.ensemble import IsolationForest
    from sklearn.model_selection import train_test_split
    
    # Performing PCA
    X = data.iloc[:,0:5].values
    pca = PCA(n_components=2)
    X = pca.fit(StandardScaler().fit_transform(X)).transform(StandardScaler().fit_transform(X))
    
    # Spliting the observations into 75% training and 25% testing
    X_train, X_test = train_test_split(X, test_size=0.25, random_state=42)
    
    # Isolation forest classifier intialization and generate results
    classifier = IsolationForest(n_estimators=50)
    classifier.fit(X_train)
    Y_pred_train = classifier.predict(X_train)
    Y_pred_test = classifier.predict(X_test)
    n_error_train = Y_pred_train[Y_pred_train == -1].size
    n_error_test = Y_pred_test[Y_pred_test == -1].size
    error_train = n_error_train / Y_pred_train.shape[0] * 100
    error_novel = n_error_test / Y_pred_test.shape[0] * 100
    
    # Visualization
    plt.clf()
    myFig = plt.figure(figsize=[10,8])
    xx, yy = np.meshgrid(np.linspace(-2, 9, 500), np.linspace(-2, 5, 500))
    Z = classifier.decision_function(np.c_[xx.ravel(), yy.ravel()])
    Z = Z.reshape(xx.shape)
    plt.contourf(xx, yy, Z, cmap=plt.cm.Blues_r)
    s = 60
    b1 = plt.scatter(X_train[:, 0], X_train[:, 1], c='white', s=s, edgecolors='k')
    b2 = plt.scatter(X_test[:, 0], X_test[:, 1], c='gold', s=s, edgecolors='k')
    plt.axis('tight')
    plt.legend([b1, b2],
               ["Training Observations", "New Regular Observations"],
               loc="best", prop=matplotlib.font_manager.FontProperties(size=14))
    plt.xlabel("Error Train: %.2f%% and Error Novel Regular: %.2f%%" % (error_train, error_novel), fontsize=13, weight="bold")
    plt.yticks(fontsize=14)
    plt.xticks(fontsize=14)
    plt.title('Novelty Detection using Isolation Forest of Ransomware Families\'\nAll Sequence Counts from 15 minutes of IRP Logs', fontsize=14, weight='bold')
    plt.show()
    
    # Save figure
    myFig.savefig('sequence_mining_analysis/Results/novelty_detection/Isolation_Forest/15_mins_sequences_all.png', format='png', dpi=150)
    myFig.savefig('sequence_mining_analysis/Results/novelty_detection/Isolation_Forest/15_mins_sequences_all.eps', format='eps', dpi=1200)
   
    
def perform_local_outlier_factor_novelty_detection(data):
    ''' With the five patterns' counts, this method performs Local Outlier Factor that computes
    the local density deviation of a given data point with respect to its neighbors.
    
    The experimentation is performed with different time chunks and number of sequences. '''
    
    # Importing necessary libraries
    from sklearn.neighbors import LocalOutlierFactor
    from sklearn.model_selection import train_test_split
    
    X = data.iloc[:,0:4].values
    pca = PCA(n_components=2)
    X = pca.fit(StandardScaler().fit_transform(X)).transform(StandardScaler().fit_transform(X))
    
    # Spliting the observations into 75% training and 25% testing
    X_train, X_test = train_test_split(X, test_size=0.25, random_state=42)
    
    # Local Outlier Factor classifier intialization and generate results
    classifier = LocalOutlierFactor(n_neighbors=20, novelty=True, contamination=0.1)
    classifier.fit(X_train)
    Y_pred_train = classifier.predict(X_train)
    Y_pred_test = classifier.predict(X_test)
    n_error_train = Y_pred_train[Y_pred_train == -1].size
    n_error_test = Y_pred_test[Y_pred_test == -1].size
    error_train = n_error_train / Y_pred_train.shape[0] * 100
    error_novel = n_error_test / Y_pred_test.shape[0] * 100
    
    # Visualization
    plt.clf()
    myFig = plt.figure(figsize=[10,8])
    xx, yy = np.meshgrid(np.linspace(-3, 8, 500), np.linspace(-2.5, 4, 500))
    Z = classifier.decision_function(np.c_[xx.ravel(), yy.ravel()])
    Z = Z.reshape(xx.shape)
    plt.contourf(xx, yy, Z, levels=np.linspace(Z.min(), 0, 7), cmap=plt.cm.PuBu)
    a = plt.contour(xx, yy, Z, levels=[0], linewidths=2, colors='darkred')
    plt.contourf(xx, yy, Z, levels=[0, Z.max()], colors='palevioletred')
    s = 60
    b1 = plt.scatter(X_train[:, 0], X_train[:, 1], c='white', s=s, edgecolors='k')
    b2 = plt.scatter(X_test[:, 0], X_test[:, 1], c='gold', s=s, edgecolors='k')
    plt.axis('tight')
    plt.legend([a.collections[0], b1, b2],
               ["Learned Frontier", "Training Observations", "New Regular Observations"],
               loc="best", prop=matplotlib.font_manager.FontProperties(size=14))
    plt.xlabel("Error Train: %.2f%% and Error Novel Regular: %.2f%%" % (error_train, error_novel), fontsize=13, weight="bold")
    plt.yticks(fontsize=14)
    plt.xticks(fontsize=14)
    plt.title('Novelty Detection using Local Outlier Factor of Ransomware Families\'\nSequence #1, #2, #3, and #4 Counts from 15 minutes of IRP Logs', fontsize=14, weight='bold')
    plt.show()
    
    # Save figure
    myFig.savefig('sequence_mining_analysis/Results/novelty_detection/Local_Outlier_Factor/15_mins_sequences_1_2_3_4.png', format='png', dpi=150)
    myFig.savefig('sequence_mining_analysis/Results/novelty_detection/Local_Outlier_Factor/15_mins_sequences_1_2_3_4.eps', format='eps', dpi=1200)
    

def perform_robust_covariance_novelty_detection(data):
    ''' With the five patterns' counts, this method performs Robust Covariance that can help concentrate on a relevant cluster when outlying points exist.
    The experimentation is performed with different time chunks and number of sequences. '''
    
    # Importing necessary libraries
    from sklearn.covariance import EllipticEnvelope
    from sklearn.model_selection import train_test_split
    
    X = data.iloc[:,0:5].values
    pca = PCA(n_components=2)
    X = pca.fit(StandardScaler().fit_transform(X)).transform(StandardScaler().fit_transform(X))
    
    # Spliting the observations into 75% training and 25% testing
    X_train, X_test = train_test_split(X, test_size=0.25, random_state=42)
    
    # Robust Covariance classifier intialization and generate results
    classifier = EllipticEnvelope(contamination=0.25)
    classifier.fit(X_train)
    Y_pred_train = classifier.predict(X_train)
    Y_pred_test = classifier.predict(X_test)
    n_error_train = Y_pred_train[Y_pred_train == -1].size
    n_error_test = Y_pred_test[Y_pred_test == -1].size
    error_train = n_error_train / Y_pred_train.shape[0] * 100
    error_novel = n_error_test / Y_pred_test.shape[0] * 100
    
    # Visualization
    plt.clf()
    myFig = plt.figure(figsize=[10,8])
    xx, yy = np.meshgrid(np.linspace(-4.5, 8.5, 500), np.linspace(-4.5, 4.5, 500))
    Z = classifier.decision_function(np.c_[xx.ravel(), yy.ravel()])
    Z = Z.reshape(xx.shape)
    plt.contourf(xx, yy, Z, levels=np.linspace(Z.min(), 0, 7), cmap=plt.cm.PuBu)
    a = plt.contour(xx, yy, Z, levels=[0], linewidths=2, colors='darkred')
    plt.contourf(xx, yy, Z, levels=[0, Z.max()], colors='palevioletred')
    s = 60
    b1 = plt.scatter(X_train[:, 0], X_train[:, 1], c='white', s=s, edgecolors='k')
    b2 = plt.scatter(X_test[:, 0], X_test[:, 1], c='gold', s=s, edgecolors='k')
    plt.axis('tight')
    plt.legend([a.collections[0], b1, b2],
               ["Learned Frontier", "Training Observations", "New Regular Observations"],
               loc="best", prop=matplotlib.font_manager.FontProperties(size=14))
    plt.xlabel("Error Train: %.2f%% and Error Novel Regular: %.2f%%" % (error_train, error_novel), fontsize=13, weight="bold")
    plt.yticks(fontsize=14)
    plt.xticks(fontsize=14)
    plt.title('Novelty Detection using Robust Covariance of Ransomware Families\'\nAll Sequence Counts from 15 minutes of IRP Logs', fontsize=14, weight='bold')
    plt.show()
    
    # Save figure
    myFig.savefig('sequence_mining_analysis/Results/novelty_detection/Robust_Covariance/15_mins_sequences_all.png', format='png', dpi=150)
    myFig.savefig('sequence_mining_analysis/Results/novelty_detection/Robust_Covariance/15_mins_sequences_all.eps', format='eps', dpi=1200)


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
        ransomware_family_names.append(key)
        
    data = {'bc': [],
            'bcC': [],
            'bcG': [],
            'EGbc': [],
            'EGbcC': [],
            'family_name': []}
    
    for family_name in ransomware_family_names:
        for i in range(3):
            data['bc'].append(bc_sequence_dict[family_name][i])
            data['bcC'].append(bcC_sequence_dict[family_name][i])
            data['bcG'].append(bcG_sequence_dict[family_name][i])
            data['EGbc'].append(EGbc_sequence_dict[family_name][i])
            data['EGbcC'].append(EGbcC_sequence_dict[family_name][i])
            data['family_name'].append(family_name)
            
    data = pd.DataFrame(data)
    print(data.head())
    
    # Visualize the clusters with PCA
    explore_cluster_in_pattern_counts(data)

    # Performing One-Class SVM classifier for novelty detection
    perform_one_class_svm_novelty_detection(data)
    
    # Performing Isolation Forest classifier for novelty detection
    perform_isolation_forest_novelty_detection(data)
    
    # Performing Local Outlier Factor (LOF) classifier for novelty detection
    perform_local_outlier_factor_novelty_detection(data)
    
    # Performing Robust Covariance classifier for novelty detection
    perform_robust_covariance_novelty_detection(data)
    
    # Deleting the dataframe and certain variables
    del (data, ransomware_family_names)
    
    ''' (This section of the work has been omitted due to poor performance)
    The following is the dataset of all five sequences based on the emprical analysis, that
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