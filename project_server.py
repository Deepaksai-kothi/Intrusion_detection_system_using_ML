from flask import Flask, render_template, request, jsonify
import pandas as pd
import joblib
import numpy as np

app = Flask(__name__)

MODEL_PATH = 'random_forest_model.pkl'
model = joblib.load(MODEL_PATH)
print("DEBUG: Model n_features_in_:", model.n_features_in_)

# Optional: Try a dummy input
try:
    dummy = np.zeros((1, model.n_features_in_))
    model.predict(dummy)
    print("DEBUG: Model accepted dummy input with shape:", dummy.shape)
except Exception as e:
    print("DEBUG: Dummy input test failed:", e)

# Expected feature columns (in order)
FEATURE_COLUMNS = [
    'logged_in', 'root_shell', 'su_attempted', 'duration', 'src_bytes', 'dst_bytes',
    'hot', 'num_failed_logins', 'num_compromised', 'num_file_creations',
    'num_shells', 'num_access_files', 'count', 'srv_count', 'serror_rate',
    'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'dst_host_count',
    'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
    'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'level', 'zero_feature_count'
]

@app.route('/')
def home():
    return render_template('homepage.html')

@app.route('/predict-file', methods=['POST'])
def predict_file():
    try:
        file = request.files['file']
        if not file:
            return jsonify({'error': "No file uploaded"})

        df = pd.read_csv(file)

        if 'Unnamed: 0' in df.columns:
            df = df.drop(columns=['Unnamed: 0'])
        df = df.drop(df.columns[0], axis=1)  # drop IP or first column if needed

        missing = [col for col in FEATURE_COLUMNS if col not in df.columns]
        for col in missing:
            df[col] = 0

        df = df[[col for col in FEATURE_COLUMNS if col in df.columns]]

        if df.shape[1] != model.n_features_in_:
            return jsonify({'error': f"Feature mismatch: expected {model.n_features_in_}, got {df.shape[1]}"})

        predictions = model.predict(df)

        label_mapping = {
            "normal": "No Intrusion",
            "dos": "Intrusion Detected - DOS",
            "probe": "Intrusion Detected - PROBE",
            "r2l": "Intrusion Detected - R2L",
            "u2r": "Intrusion Detected - U2R"
        }

        results = [label_mapping.get(pred, "Unknown") for pred in predictions]

        return jsonify({'predictions': results})

    except Exception as e:
        print("ERROR:", e)
        return jsonify({'error': str(e)})

@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.form.to_dict()
        input_df = pd.DataFrame([data])

        # Convert to correct types
        input_df = input_df.astype(float)

        # Handle missing features
        missing = [col for col in FEATURE_COLUMNS if col not in input_df.columns]
        for col in missing:
            input_df[col] = 0

        input_df = input_df[[col for col in FEATURE_COLUMNS if col in input_df.columns]]

        if input_df.shape[1] != model.n_features_in_:
            return jsonify({'error': f"Feature mismatch: expected {model.n_features_in_}, got {input_df.shape[1]}"})

        prediction = model.predict(input_df)[0]

        label_mapping = {
            "normal": "No Intrusion",
            "dos": "Intrusion Detected - DOS",
            "probe": "Intrusion Detected - PROBE",
            "r2l": "Intrusion Detected - R2L",
            "u2r": "Intrusion Detected - U2R"
        }

        result = label_mapping.get(prediction, "Unknown")
        return jsonify({'prediction': result})

    except Exception as e:
        print("ERROR in /predict:", e)
        return jsonify({'error': str(e)})

if __name__ == '__main__':
    app.run(debug=True)
