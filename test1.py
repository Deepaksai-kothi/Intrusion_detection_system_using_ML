import pandas as pd

df = pd.read_csv("NSS-KDD.csv")
print("Columns in training data:\n", df.columns.tolist())
