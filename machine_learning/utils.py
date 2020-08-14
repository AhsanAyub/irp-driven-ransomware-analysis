#!/usr/bin/env python3

__author__ = "Md. Ahsan Ayub"
__license__ = "GPL"
__credits__ = ["Ayub, Md. Ahsan", "Siraj, Ambareen"]
__maintainer__ = "Md. Ahsan Ayub"
__email__ = "mayub42@tntech.edu"
__status__ = "Prototype"

# Import libraries
import pandas as pd
import numpy as np

from sklearn.preprocessing import MinMaxScaler
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import (classification_report, accuracy_score, precision_score, recall_score, f1_score)

import helper as helper


def generate_all_ransomware_family_dataset(time_chuck):
    ''' This utility method processes all the ransomware families' datasets up to time
    chunk passed as argument. The method will process the dataset and return the final dataframe.
    
    Time chunks will represent in 5 minutes interval datasets, i.e., 10 mins value for time chucks
    will be denoted as 2 because 10 / 5 is 2. '''
    
    time_chuck = round(time_chuck / 5)
    
    # Main dataframe to store all the dataset
    master_dataset = pd.DataFrame()
    
    # Get all the ransomware families' paths
    ransomsomware_family_paths = helper.get_all_ransomsomware_family_paths()
    
    # Take out the ransomware family names
    ransomware_family_names = [i.split('/')[-1 ] for i in ransomsomware_family_paths]
    
    for i in range(len(ransomsomware_family_paths)):
        # Get a certain ransowmare family's file paths up to time chunks
        ransomware_dataset_paths = helper.get_ransomsomware_family_datasete_paths(ransomsomware_family_paths[i])
        
        for ransomware_dataset_path in ransomware_dataset_paths:
            
            # Ignore the files that do not fall in the desired time chunks
            for j in range(1,time_chuck+1):
                if('_' + str(j) + '.pkl.gz' in ransomware_dataset_path):  
                    
                    dataset = pd.read_pickle(ransomware_dataset_path, compression='gzip')
                    
                    # Family ID will be the name of the ransomware family
                    dataset['family_id'] = ransomware_family_names[i]
                    dataset = dataset.drop(dataset[(dataset['class'] != 1)].index)    # Only taking the ransomware instances
                
                    '''' Process the dataset before passing it to the master dataframe '''
                    
                    # Dropping the columns that are not needed for analysis
                    dataset = dataset.drop(['sequence_number', 'process_name', 'device_object', 'file_object', 'transaction',
                                            'pre_operation_time', 'post_operation_time', 'file_name', 'inform', 'arg1',
                                            'arg2', 'arg3', 'arg4', 'arg5', 'arg6', 'class'], axis=1)
                    
                    # Convert data type of certain dataframe rows
                    dataset['irp_nocache'] = dataset['irp_nocache'].astype(int)
                    dataset['irp_paging_io'] = dataset['irp_paging_io'].astype(int)
                    dataset['irp_synchoronous_api'] = dataset['irp_synchoronous_api'].astype(int)
                    dataset['irp_synchoronous_paging_io'] = dataset['irp_synchoronous_paging_io'].astype(int)
                    dataset['status'] = dataset['status'].apply(hex)
                    dataset['irp_flag'] = dataset['irp_flag'].apply(hex)
                    
                    # Passing the dataset to the master dataframne
                    master_dataset = pd.concat([master_dataset, dataset])
        
        print("%d out of %d ransomware family dataset loaded" % (i+1, len(ransomsomware_family_paths)))
            
    master_dataset.reset_index(drop=True)
    master_dataset = pd.get_dummies(master_dataset, columns=['major_operation_type', 'minor_operation_type', 'irp_flag', 'status'], drop_first=True)
    
    scalar = MinMaxScaler()
    master_dataset[['process_id', 'thread_id', 'parent_id']] = scalar.fit_transform(master_dataset[['process_id', 'thread_id', 'parent_id']])
    
    return master_dataset


def model_compilation(X, Y, classifier):
    ''' This utility function ensures a generic cross validation implementation
    for compilation of a classifier.
    
    The function returns accuracy, precision, recall, and F1 scores. '''
    
    cv = StratifiedKFold(n_splits=5, random_state=None, shuffle=False)
    accuracy_scores = []
    precision_scores = []
    recall_scores = []
    f1_scores = []
    
    for train, test in cv.split(X, Y):
        # Spliting the dataset
        X_train, X_test, Y_train, Y_test = X[train], X[test], Y[train], Y[test]
        
        # Fitting the classifier into training set
        classifier = classifier.fit(X_train, Y_train)
        
        # Breakdown of statistical measure based on classes
        Y_pred = classifier.predict(X_test)
        print(classification_report(Y_test, Y_pred, digits=4))
        
        # Compute the model's performance
        accuracy_scores.append(accuracy_score(Y_test, Y_pred))
        f1_scores_temp = []
        f1_scores_temp.append(f1_score(Y_test, Y_pred, average=None))
        f1_scores.append(np.mean(f1_scores_temp))
        del f1_scores_temp
        
        precision_scores_temp = []
        precision_scores_temp.append(precision_score(Y_test, Y_pred, average=None))
        precision_scores.append(np.mean(precision_scores_temp))
        del precision_scores_temp
        
        recall_scores_temp = []
        recall_scores_temp.append(recall_score(Y_test, Y_pred, average=None))
        recall_scores.append(np.mean(recall_scores_temp))
        del recall_scores_temp

    return accuracy_scores, precision_scores, recall_scores, f1_scores


def decision_tree(X, Y):
    ''' Implementation of decision tree classifier provided X and Y instances are
    received from somewhere else. It utilizes 5-fold stratified cross validation
    for compilation and reports model's performance.'''
    
    # Importing library for decision tree
    from sklearn import tree
    
    # Compiling the model with recording statistical scores for model evaluation
    accuracy_scores, precision_scores, recall_scores, f1_scores = model_compilation(X, Y, tree.DecisionTreeClassifier())
    
    # Statistical measurement of the model
    print(" ======= Decision Tree ======= ")
    print("Accuracy: ", np.mean(accuracy_scores))
    print("Precision: ", np.mean(precision_scores))
    print("Recall: ", np.mean(recall_scores))
    print("F1: ", np.mean(f1_scores))
    

def nearest_neighbors(X, Y):
    ''' This method implements K-nearest neighbor and nearest centroid classifiers
    from the nearest neighbors ML family. It utilizes 5-fold stratified cross validation
    for compilation and reports models' performances. '''
    
    # Importing library
    from sklearn import neighbors
    
    # Compiling the model with recording statistical scores for KNN evaluation
    accuracy_scores, precision_scores, recall_scores, f1_scores = model_compilation(X, Y, neighbors.KNeighborsClassifier(15, weights='uniform'))
    
    # Statistical measurement of the model
    print(" ======= KNN (neighbor = 5 and weight = uniform) ======= ")
    print("Accuracy: ", np.mean(accuracy_scores))
    print("Precision: ", np.mean(precision_scores))
    print("Recall: ", np.mean(recall_scores))
    print("F1: ", np.mean(f1_scores))
    
    # Compiling the model with recording statistical scores for Nearest Neighbor's evaluation
    accuracy_scores, precision_scores, recall_scores, f1_scores = model_compilation(X, Y, neighbors.NearestCentroid())
    
    # Statistical measurement of the model
    print(" ======= Nearest Centroid ======= ")
    print("Accuracy: ", np.mean(accuracy_scores))
    print("Precision: ", np.mean(precision_scores))
    print("Recall: ", np.mean(recall_scores))
    print("F1: ", np.mean(f1_scores))
    
    
def bagging(X, Y):
    ''' This method implements Random Forest, Extra Tree, and Bagging classifiers
    from the bagging ML family. It utilizes 5-fold stratified cross validation
    for compilation and reports models' performances. '''
    
    # Importing libraries
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.ensemble import ExtraTreesClassifier
    from sklearn.ensemble import BaggingClassifier
    
    # Compiling the model with recording statistical scores for Random Forest's evaluation
    accuracy_scores, precision_scores, recall_scores, f1_scores = model_compilation(X, Y, RandomForestClassifier(n_estimators = 100))
    
    # Statistical measurement of the model
    print(" ======= Random Forest Classifier (100 estimator) ======= ")
    print("Accuracy: ", np.mean(accuracy_scores))
    print("Precision: ", np.mean(precision_scores))
    print("Recall: ", np.mean(recall_scores))
    print("F1: ", np.mean(f1_scores))
    
    # Compiling the model with recording statistical scores for Extra Tree classifier's evaluation
    accuracy_scores, precision_scores, recall_scores, f1_scores = model_compilation(X, Y, ExtraTreesClassifier(n_estimators = 100))
    
    # Statistical measurement of the model
    print(" ======= Extra Tree Classifier (100 estimator) ======= ")
    print("Accuracy: ", np.mean(accuracy_scores))
    print("Precision: ", np.mean(precision_scores))
    print("Recall: ", np.mean(recall_scores))
    print("F1: ", np.mean(f1_scores))
    
    # Compiling the model with recording statistical scores for Bagging classifier's evaluation
    accuracy_scores, precision_scores, recall_scores, f1_scores = model_compilation(X, Y, BaggingClassifier(base_estimator = None, n_estimators = 100))
    
    # Statistical measurement of the model
    print(" ======= Bagging Classifier Tree (100 estimator) ======= ")
    print("Accuracy: ", np.mean(accuracy_scores))
    print("Precision: ", np.mean(precision_scores))
    print("Recall: ", np.mean(recall_scores))
    print("F1: ", np.mean(f1_scores))
    
    
def boosting(X, Y):
    ''' This method implements Ada Boost, Gradient Boosting, and Histogram-based Gradient
    Boosting classifiers from the boosting ML family. It utilizes 5-fold stratified
    cross validation for compilation and reports models' performances. '''
    
    # Importing libraries
    from sklearn.ensemble import AdaBoostClassifier
    from sklearn.ensemble import GradientBoostingClassifier
    from sklearn.ensemble import HistGradientBoostingClassifier
    
    # Compiling the model with recording statistical scores for Ada Boost's evaluation
    accuracy_scores, precision_scores, recall_scores, f1_scores = model_compilation(X, Y, AdaBoostClassifier(n_estimators = 100, learning_rate = 1, algorithm = 'SAMME.R', random_state = None))
    
    # Statistical measurement of the model
    print(" ======= Ada Boost Classifier (100 estimator) ======= ")
    print("Accuracy: ", np.mean(accuracy_scores))
    print("Precision: ", np.mean(precision_scores))
    print("Recall: ", np.mean(recall_scores))
    print("F1: ", np.mean(f1_scores))
    
    # Compiling the model with recording statistical scores for Gradient Boosting's evaluation
    accuracy_scores, precision_scores, recall_scores, f1_scores = model_compilation(X, Y, GradientBoostingClassifier(criterion = 'friedman_mse'))
    
    # Statistical measurement of the model
    print(" ======= Gradient Boosting Classifier (100 estimator) ======= ")
    print("Accuracy: ", np.mean(accuracy_scores))
    print("Precision: ", np.mean(precision_scores))
    print("Recall: ", np.mean(recall_scores))
    print("F1: ", np.mean(f1_scores))
    
    # Compiling the model with recording statistical scores for Histogram-based Gradient Boosting's evaluation
    accuracy_scores, precision_scores, recall_scores, f1_scores = model_compilation(X, Y, HistGradientBoostingClassifier())
    
    # Statistical measurement of the model
    print(" ======= Histogram-based Gradient Boosting Classifier Tree (100 estimator) ======= ")
    print("Accuracy: ", np.mean(accuracy_scores))
    print("Precision: ", np.mean(precision_scores))
    print("Recall: ", np.mean(recall_scores))
    print("F1: ", np.mean(f1_scores))
    
    
def support_vector_machine(X, Y):
    ''' This method implements Support Vector Machines (SVMs). It utilizes SVM's linear,
    gaussian, and polynomial kernels' classifiers and 5-fold stratified cross validation for
    compilation and reports models' performances. '''
    
    # Importing library
    from sklearn.svm import SVC
    
    # Compiling the model with recording statistical scores for SVM Linear's evaluation
    accuracy_scores, precision_scores, recall_scores, f1_scores = model_compilation(X, Y, SVC(kernel = 'linear', gamma = 'scale'))
    
    # Statistical measurement of the model
    print(" ======= SVM (Linear Kernel) ======= ")
    print("Accuracy: ", np.mean(accuracy_scores))
    print("Precision: ", np.mean(precision_scores))
    print("Recall: ", np.mean(recall_scores))
    print("F1: ", np.mean(f1_scores))
    
    # Compiling the model with recording statistical scores for SVM Gaussian's evaluation
    accuracy_scores, precision_scores, recall_scores, f1_scores = model_compilation(X, Y, SVC(kernel = 'rbf', gamma = 'scale'))
    
    # Statistical measurement of the model
    print(" ======= SVM (Gaussian Kernel) ======= ")
    print("Accuracy: ", np.mean(accuracy_scores))
    print("Precision: ", np.mean(precision_scores))
    print("Recall: ", np.mean(recall_scores))
    print("F1: ", np.mean(f1_scores))
    
    # Compiling the model with recording statistical scores for SVM Polynomial's evaluation
    accuracy_scores, precision_scores, recall_scores, f1_scores = model_compilation(X, Y, SVC(kernel = 'poly', gamma = 'scale'))
    
    # Statistical measurement of the model
    print(" ======= SVM (Polynomial Kernel) ======= ")
    print("Accuracy: ", np.mean(accuracy_scores))
    print("Precision: ", np.mean(precision_scores))
    print("Recall: ", np.mean(recall_scores))
    print("F1: ", np.mean(f1_scores))


def linear_model(X, Y):
    ''' This method implements Logistic Regression classifier from linear model ML family.
    It utilizes 5-fold stratified cross validation for compilation and reports models' performances. '''
    
    # Importing library
    from sklearn.linear_model import LogisticRegression
    
    # Compiling the model with recording statistical scores for logistic regression's evaluation
    accuracy_scores, precision_scores, recall_scores, f1_scores = model_compilation(X, Y, LogisticRegression(random_state = 0, multi_class = 'auto', solver = 'lbfgs'))
    
    # Statistical measurement of the model
    print(" ======= Logistic Regression ======= ")
    print("Accuracy: ", np.mean(accuracy_scores))
    print("Precision: ", np.mean(precision_scores))
    print("Recall: ", np.mean(recall_scores))
    print("F1: ", np.mean(f1_scores))
    
    
def discriminant_analysis(X, Y):
    ''' This method implements Linear Discriminant Analysis (LDA) and Quadratic Discriminant
    Analysis (QDA) classifiers from Discriminant Analysis ML family. It utilizes 5-fold
    stratified cross validation for compilation and reports models' performances. '''
    
    # Importing libraries
    from sklearn.discriminant_analysis import LinearDiscriminantAnalysis
    from sklearn.discriminant_analysis import QuadraticDiscriminantAnalysis
    
    # Compiling the model with recording statistical scores for LDA's evaluation
    accuracy_scores, precision_scores, recall_scores, f1_scores = model_compilation(X, Y, LinearDiscriminantAnalysis(solver='svd'))
    
    # Statistical measurement of the model
    print(" ======= LDA ======= ")
    print("Accuracy: ", np.mean(accuracy_scores))
    print("Precision: ", np.mean(precision_scores))
    print("Recall: ", np.mean(recall_scores))
    print("F1: ", np.mean(f1_scores))
    
    # Compiling the model with recording statistical scores for QDA's evaluation
    accuracy_scores, precision_scores, recall_scores, f1_scores = model_compilation(X, Y, QuadraticDiscriminantAnalysis())
    
    # Statistical measurement of the model
    print(" ======= QDA ======= ")
    print("Accuracy: ", np.mean(accuracy_scores))
    print("Precision: ", np.mean(precision_scores))
    print("Recall: ", np.mean(recall_scores))
    print("F1: ", np.mean(f1_scores))
    
    
def gaussian_processes(X, Y):
    ''' This method implements Gaussian Process classifier. It utilizes 5-fold
    stratified cross validation for compilation and reports models' performances. '''
    
    # Importing library
    from sklearn.gaussian_process import GaussianProcessClassifier
    
    # Compiling the model with recording statistical scores for GP's evaluation
    accuracy_scores, precision_scores, recall_scores, f1_scores = model_compilation(X, Y, GaussianProcessClassifier(kernel = None, optimizer='fmin_l_bfgs_b'))
    
    # Statistical measurement of the model
    print(" ======= Gaussian Process Classifier ======= ")
    print("Accuracy: ", np.mean(accuracy_scores))
    print("Precision: ", np.mean(precision_scores))
    print("Recall: ", np.mean(recall_scores))
    print("F1: ", np.mean(f1_scores))
    
    
def neural_networks(X, Y):
    ''' This method implements Multilayer Perceptron (MLP) classifier from neural network ML family. '''
    
    # Importing the Keras libraries and packages
    from keras.models import Sequential
    from keras.layers import Dense
    from keras.callbacks import EarlyStopping
    
    from sklearn.model_selection import train_test_split
    import random
    
    # Split the dataset into training (80%) and testing (20%) set
    X_train, X_test, Y_train, Y_test = train_test_split(X, Y, test_size = 0.2, random_state = 42, stratify=Y)
    
    # Initializing the MLP model
    model = Sequential()
    
    # The number of hidden layer is less than twice the size of the input layer
    output_dim = (X.shape[1] - random.randint(1, round(X.shape[1]))) * 2
    
    # Adding the input layer and the first hidden layer
    model.add(Dense(units = output_dim, kernel_initializer = "uniform", activation = "relu", input_shape = (X.shape[1],)))
    
    # Adding the second hidden layer
    model.add(Dense(units = output_dim, kernel_initializer = "uniform", activation = "relu"))
    
    if(len(np.unique(Y)) > 2):    # Multi-classification task
        # Adding the output layer
        model.add(Dense(units = len(np.unique(Y)), kernel_initializer = "uniform", activation = "softmax"))
        
        # Compiling the MLP
        model.compile(optimizer = "adam", loss = "sparse_categorical_crossentropy", metrics = ['accuracy'])
        
    else:    # Binary classification task
        # Adding the output layer
        model.add(Dense(units = 1, kernel_initializer =  "uniform", activation = "sigmoid"))
        # Compiling the MLP
        model.compile(optimizer = "adam", loss = "binary_crossentropy", metrics = ['accuracy'])
    
    print(model.summary())
    
    # Callback to stop if validation loss does not decrease
    callbacks = [EarlyStopping(monitor = "val_loss", patience=3)]
    
    # Fitting the MLP to the Training set
    history = model.fit(X_train, Y_train, callbacks = callbacks, validation_split = 0.15,
                        batch_size = 128, epochs = 2, shuffle = True)
    
    print(history.history)
    
    del (X, Y, X_train, Y_train)
    
    # Predicting the results given instances X_test
    Y_pred = model.predict_classes(X_test)
    
    print("\n ======= Multilayer Perceptron (MLP) ======= ")
    if(len(np.unique(Y_test))) == 2: # Binary classification task
        Y_pred = (Y_pred > 0.5)
        print("F1: ", f1_score(Y_test, Y_pred, average='binary'))
        print("Precison: ", precision_score(Y_test, Y_pred, average='binary'))
        print("Recall: ", recall_score(Y_test, Y_pred, average='binary'))
    
    else:   # Multi-classification task
        f1_scores = f1_score(Y_test, Y_pred, average=None)
        print("F1: ", np.mean(f1_scores))
        precision_scores = precision_score(Y_test, Y_pred, average=None)
        print("Precison: ", np.mean(precision_scores))
        recall_scores = recall_score(Y_test, Y_pred, average=None)
        print("Recall: ", np.mean(recall_scores))
    
    print("Accuracy: ", accuracy_score(Y_test, Y_pred))    
    
    # Breakdown of statistical measure based on classes
    print(classification_report(Y_test, Y_pred, digits=4))