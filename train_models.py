""" Initial stuff - imports, loading the dataset"""
import joblib
import pandas as pd
import numpy as np

# Classifiers
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from xgboost import XGBClassifier
import shap

# Training + test split
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn import preprocessing
from sklearn.pipeline import Pipeline, make_pipeline
from sklearn.preprocessing import StandardScaler

# Accuracy score
from sklearn.metrics import accuracy_score

# Loading the dataset
df = pd.read_csv("domain_dataset.csv", header=0, na_values=["?"])


""" Preprocessing the dataset - cleaning, target encoding, retyping, dropping NaN """

target_cols = ["Registrar", "Location"]

df.dropna(inplace=True)

# Target encodings for main
target_encodings = {}

# Global mean of Class
global_mean = df["Class"].mean()

# Smoothing factor for TE
m = 3  

# Target Encoding + Smoothing
for col in target_cols:
    # Compute category mean
    encoding = df.groupby(col)["Class"].mean()
    
    # Compute category size
    counts = df.groupby(col)["Class"].count()
    
    # Apply smoothing formula
    smoothed_encoding = (encoding * counts + m * global_mean) / (counts + m)
    
    # Store encoding for future use
    target_encodings[col] = smoothed_encoding
    
    # Apply encoding to the dataset (fill new categories with global mean)
    df[col] = df[col].map(smoothed_encoding).fillna(global_mean)

# Domain name doesn't aid in the training so we drop it + Class is the target
X = df.drop(columns=['Domain', 'Server', 'SSL_Issuer', 'AS', 'SSL_TTL', 'Entropy', 'HTTP_Status', 'Is_Unicode', 'Class'])

# Convert boolean columns to integers
bool_columns = X.select_dtypes(include=['bool']).columns
for col in bool_columns:
    X[col] = X[col].astype(int)

y = df["Class"]

""" Dividing the preprocessed dataset into training and testing split - testing is 20% """
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

""" ====== Logistic Regression ====== """

# We scale the data for Logistic Regression - needed to converge + better performance
pipe = make_pipeline(StandardScaler(), LogisticRegression(max_iter=5000))

# CV
cv_score_lr = cross_val_score(pipe, X_train, y_train, cv=5, scoring='accuracy')

# Training
pipe.fit(X_train, y_train)  
y_pred = pipe.predict(X_test)

# Evaluation
test_score_lr = accuracy_score(y_test, y_pred)
print("--- Logistic Regression ---")
print("Cross-validation scores:", cv_score_lr)
print("Average CV Score:", cv_score_lr.mean())
print("Test Accuracy:", test_score_lr)

""" ====== Random Forest ====== """
rf = RandomForestClassifier(random_state=42)

# Cross-validation score
cv_score_rf = cross_val_score(rf, X_train, y_train, cv=5, scoring='accuracy')

# Training
rf.fit(X_train, y_train)

# Prediction
y_pred_rf = rf.predict(X_test)

# Accuracy
test_score_rf = accuracy_score(y_test, y_pred_rf)
print("\n--- Random Forest ---")
print("Cross-validation scores:", cv_score_rf)
print("Average CV Score:", cv_score_rf.mean())
print("Test Accuracy:", test_score_rf)

""" ====== XGB ====== """
xgb = XGBClassifier(eval_metric="logloss")

# CV
cv_score_xgb = cross_val_score(xgb, X_train, y_train, cv=5, scoring='accuracy') 

# Training
xgb.fit(X_train, y_train)

# Prediction
y_pred_xgb = xgb.predict(X_test)

# Accuracy
test_score_xgb = accuracy_score(y_test, y_pred_xgb)
print("\n--- XGBoost ---")
print("Cross-validation scores:", cv_score_xgb)
print("Average CV Score:", cv_score_xgb.mean())
print("Test Accuracy:", test_score_xgb)




try:
    joblib.dump(pipe, "log_reg_model.pkl")
    joblib.dump(rf, "rf_model.pkl")
    joblib.dump(xgb, "xgb_model.pkl")

    joblib.dump(target_encodings, "target_encodings.pkl")
    joblib.dump(global_mean, "global_mean.pkl")

    scaler = StandardScaler()
    scaler.fit(X_train)
    joblib.dump(scaler, "scaler.pkl")

    print("\nModels trained and saved successfully!")

# TODO: Add proper error message
except Exception as e: 
    print("There was a problem with saving the models.")