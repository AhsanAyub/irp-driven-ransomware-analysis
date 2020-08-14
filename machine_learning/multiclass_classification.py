#!/usr/bin/env python3

__author__ = "Md. Ahsan Ayub"
__license__ = "GPL"
__credits__ = ["Ayub, Md. Ahsan", "Siraj, Ambareen"]
__maintainer__ = "Md. Ahsan Ayub"
__email__ = "mayub42@tntech.edu"
__status__ = "Prototype"


# Import libraries
from sklearn import preprocessing
import machine_learning.utils as utility


# Driver program
if __name__ == '__main__':
    
    final_time_count = 5
    dataset = utility.generate_all_ransomware_family_dataset(final_time_count)    # Get the datasets of 5 minutes
    
    # Build target class (multiclass)
    Y = dataset['family_id']
    le = preprocessing.LabelEncoder()
    le.fit(Y)
    Y = le.transform(Y)
    
    # Build X observations
    X = dataset.drop(['family_id'], axis=1).iloc[:,:].values
    del dataset
    
    print("Dataset used up to %d minutes" % final_time_count)
    
    ''' Decision Tree classifier for multiclass classification with the processed dataset '''
    utility.decision_tree(X, Y)
    
    ''' KNN and Nearest Centroid classifiers for multiclass classification with the processed dataset '''
    utility.nearest_neighbors(X, Y)
    
    ''' Random Forest, Extra Tree, and Bagging classifiers for multiclass classification with the processed dataset '''
    utility.bagging(X, Y)
    
    ''' Ada Boost, Gradient Boosting, and Histogram-based Gradient Boosting classifiers for multiclass classification with the processed dataset '''
    utility.boosting(X, Y)
    
    ''' SVM's linear, gaussian, and polynomial kernels' classifiers for multiclass classification with the processed dataset '''
    utility.support_vector_machine(X, Y)
    
    ''' Logistic Regression classifier for multiclass classification with the processed dataset '''
    utility.linear_model(X, Y)
    
    ''' Linear Discriminant Analysis (LDA) and Quadratic Discriminant Analysis (QDA) classifiers for multiclass classification with the processed dataset '''
    utility.discriminant_analysis(X, Y)
    
    ''' Gaussian Process (GP) classifier for multiclass classification with the processed dataset '''
    utility.linear_model(X, Y)
    
    ''' Multilayer Perceptron (MLP) classifier for multiclass classification with the processed dataset '''
    utility.linear_model(X, Y)
    
    # Delete the variables
    del (X, Y)