import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib

# Load your processed dataset
df = pd.read_csv('NSS-KDD.csv')

# Columns to use for training
FEATURE_COLUMNS = [
    'logged_in', 'root_shell', 'su_attempted', 'outcome', 'duration', 'src_bytes',
    'dst_bytes', 'hot', 'num_failed_logins', 'num_compromised', 'num_file_creations',
    'num_shells', 'num_access_files', 'count', 'srv_count', 'serror_rate',
    'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'dst_host_count',
    'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
    'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'level', 'zero_feature_count'
]

# Target column
TARGET_COLUMN = 'outcome'  # Make sure this is the column indicating attack/no attack

# Drop rows with missing target values, if any
df = df.dropna(subset=[TARGET_COLUMN])

# Prepare data
for col in FEATURE_COLUMNS:
    if col not in df.columns:
        print(f"Adding missing column: {col}")
        df[col] = 0

X = df[FEATURE_COLUMNS]
y = df[TARGET_COLUMN]

# Optional: Drop target from features if it's included accidentally
if TARGET_COLUMN in X.columns:
    X = X.drop(columns=[TARGET_COLUMN])

# Split dataset
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Evaluate
y_pred = model.predict(X_test)
print(classification_report(y_test, y_pred))

# Save the model
joblib.dump(model, 'random_forest_model.pkl')
print("Model trained and saved as 'random_forest_model.pkl'")
