import pandas as pd
import re
import time
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib  # to save/load model

# Timer start
start_time = time.time()

# Load dataset
df = pd.read_csv("Dataset549k.csv")
print(f"Dataset loaded with {len(df)} URLs")

# Feature extraction function
def extract_features(url):
    features = {
        'url_length': len(url),
        'num_dots': url.count('.'),
        'num_hyphens': url.count('-'),
        'num_slashes': url.count('/'),
        'has_https': int(url.startswith('https')),
        'has_ip': int(bool(re.match(r"http[s]?://\d+\.\d+\.\d+\.\d+", url))),
        'has_at_symbol': int('@' in url),
        'has_suspicious_word': int(any(w in url.lower() for w in ['login', 'verify', 'update', 'bank', 'secure'])),
        'count_digits': sum(c.isdigit() for c in url),
        'is_shortened': int(any(s in url.lower() for s in ['bit.ly', 'tinyurl', 'goo.gl', 't.co'])),
        'suspicious_tld': int(url.endswith(('.tk', '.ml', '.ga', '.cf', '.gq', '.xyz'))),
        'subdomain_count': url.split('//')[-1].split('/')[0].count('.') - 1,
        'contains_double_slash_redirect': int('//' in url[8:])  # skip https://
    }
    return features

# Extract features
features = df['URL'].apply(extract_features)
X = pd.DataFrame(features.tolist())
y = df['label']

# Train on full dataset
model = RandomForestClassifier(n_estimators=50, random_state=42)
model.fit(X, y)

# Predict on same data (for accuracy report)
y_pred = model.predict(X)

# Evaluation
accuracy = accuracy_score(y, y_pred) * 100
print(f"\nAccuracy: {accuracy:.2f}%")
print("\nConfusion Matrix:\n", confusion_matrix(y, y_pred))
print("\nClassification Report:\n", classification_report(y, y_pred))

# Save model
joblib.dump(model, "rf_model_phishing.pkl")
print("\nModel saved as rf_model_phishing.pkl")

# Save predictions
df_results = X.copy()
df_results['Original_URL'] = df['URL']
df_results['Actual_Label'] = y
df_results['Predicted_Label'] = y_pred
df_results = df_results[['Original_URL', 'Actual_Label', 'Predicted_Label'] + list(X.columns)]
df_results.to_csv("trained_phishing_model_results.csv", index=False)
print("Report saved as trained_phishing_model_results.csv")

# Time taken
end_time = time.time()
print(f"\nTime taken: {end_time - start_time:.2f} seconds")
