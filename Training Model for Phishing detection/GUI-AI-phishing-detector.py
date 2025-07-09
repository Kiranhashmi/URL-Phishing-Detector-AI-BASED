import joblib
import re
import pandas as pd
import tkinter as tk
from tkinter import ttk, scrolledtext

# Load the trained model
model = joblib.load("rf_model_phishing.pkl")

# Feature extraction function (must match training logic)
def extract_features(url):
    return {
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
        'contains_double_slash_redirect': int('//' in url[8:])
    }

# Function to identify suspicious features with layman-friendly explanations
def identify_suspicious_features(features):
    suspicious = []
    if features['url_length'] > 50:
        suspicious.append(f"The URL is very long ({features['url_length']} characters)")
    if features['num_dots'] > 3:
        suspicious.append(f"The URL has too many dots ({features['num_dots']} dots)")
    if features['num_hyphens'] > 2:
        suspicious.append(f"The URL has too many hyphens ({features['num_hyphens']} hyphens)")
    if features['num_slashes'] > 5:
        suspicious.append(f"The URL has too many slashes ({features['num_slashes']} slashes)")
    if features['has_https'] == 0:
        suspicious.append("The URL doesn't use HTTPS (not secure)")
    if features['has_ip'] == 1:
        suspicious.append("The URL uses an IP address instead of a domain name")
    if features['has_at_symbol'] == 1:
        suspicious.append("The URL contains an @ symbol")
    if features['has_suspicious_word'] == 1:
        suspicious.append("The URL contains words like 'login' or 'bank'")
    if features['count_digits'] > 10:
        suspicious.append(f"The URL has too many numbers ({features['count_digits']} digits)")
    if features['is_shortened'] == 1:
        suspicious.append("The URL is shortened (like bit.ly or tinyurl)")
    if features['suspicious_tld'] == 1:
        suspicious.append("The URL uses an unusual domain ending (like .tk or .xyz)")
    if features['subdomain_count'] > 1:
        suspicious.append(f"The URL has multiple subdomains ({features['subdomain_count']} subdomains)")
    if features['contains_double_slash_redirect'] == 1:
        suspicious.append("The URL has a redirect pattern (double slashes)")
    return suspicious

# Function to analyze URL and update GUI
def analyze_url():
    url = url_entry.get().strip()
    if not url:
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, "Please enter a URL to check.\n")
        return

    try:
        features = extract_features(url)
        df = pd.DataFrame([features])
        prediction = model.predict(df)[0]

        # Clear previous result
        result_text.delete(1.0, tk.END)

        # Display prediction
        if prediction == 1:
            result_text.insert(tk.END, "⚠️ Warning: This URL might be a phishing scam!\n\n", "warning")
            # Display suspicious features
            suspicious_features = identify_suspicious_features(features)
            if suspicious_features:
                result_text.insert(tk.END, "Why it looks suspicious:\n", "header")
                for feature in suspicious_features:
                    result_text.insert(tk.END, f"- {feature}\n", "suspicious")
            else:
                result_text.insert(tk.END, "It looks suspicious, but no specific issues were found.\n", "header")
        else:
            result_text.insert(tk.END, "✅ Good news: This URL seems safe!\n\n", "safe")

        # Display all feature values in simple terms
        result_text.insert(tk.END, "\nDetails about the URL:\n", "header")
        feature_descriptions = {
            'url_length': f"Length of the URL: {features['url_length']} characters",
            'num_dots': f"Number of dots: {features['num_dots']}",
            'num_hyphens': f"Number of hyphens: {features['num_hyphens']}",
            'num_slashes': f"Number of slashes: {features['num_slashes']}",
            'has_https': "Uses HTTPS (secure): Yes" if features['has_https'] else "Uses HTTPS (secure): No",
            'has_ip': "Uses an IP address: Yes" if features['has_ip'] else "Uses an IP address: No",
            'has_at_symbol': "Contains @ symbol: Yes" if features['has_at_symbol'] else "Contains @ symbol: No",
            'has_suspicious_word': "Has words like 'login' or 'bank': Yes" if features['has_suspicious_word'] else "Has words like 'login' or 'bank': No",
            'count_digits': f"Number of digits: {features['count_digits']}",
            'is_shortened': "Is a shortened URL: Yes" if features['is_shortened'] else "Is a shortened URL: No",
            'suspicious_tld': "Has unusual domain ending: Yes" if features['suspicious_tld'] else "Has unusual domain ending: No",
            'subdomain_count': f"Number of subdomains: {features['subdomain_count']}",
            'contains_double_slash_redirect': "Has redirect pattern: Yes" if features['contains_double_slash_redirect'] else "Has redirect pattern: No"
        }
        for desc in feature_descriptions.values():
            result_text.insert(tk.END, f"- {desc}\n")

    except Exception as e:
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, f"Oops, something went wrong: {e}\n", "error")

# Create GUI
root = tk.Tk()
root.title("AI Phishing Detector")
root.geometry("600x450")
root.configure(bg="#F5F6F5")  # White background

# Styling
style = ttk.Style()
style.theme_use('clam')
style.configure("TButton", padding=12, font=("Arial", 14), background="#0057B8", foreground="white")
style.map("TButton", background=[('active', '#003087')])  # Darker blue on hover
style.configure("TLabel", font=("Arial", 14), foreground="#0057B8", background="#F5F6F5")
style.configure("TEntry", fieldbackground="white", foreground="#0057B8", font=("Arial", 14))

# Layout
frame = ttk.Frame(root, padding="15", style="Custom.TFrame")
frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
frame.configure(style="Custom.TFrame")
style.configure("Custom.TFrame", background="#F5F6F5")

# URL input
ttk.Label(frame, text="Type a URL to check:").grid(row=0, column=0, sticky=tk.W, pady=10)
url_entry = ttk.Entry(frame, width=50)
url_entry.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=10)

# Analyze button
analyze_button = ttk.Button(frame, text="Check URL", command=analyze_url)
analyze_button.grid(row=2, column=0, columnspan=2, pady=15)

# Result display
result_text = scrolledtext.ScrolledText(frame, wrap=tk.WORD, width=60, height=15, font=("Arial", 12), bg="white", fg="#0057B8")
result_text.grid(row=3, column=0, columnspan=2, pady=10)

# Powered by KALS label
powered_label = ttk.Label(frame, text="Powered by KALS", font=("Arial", 10, "italic"), foreground="#0057B8", background="#F5F6F5")
powered_label.grid(row=4, column=0, columnspan=2, sticky=tk.S, pady=5)

# Configure text tags for styling
result_text.tag_configure("warning", foreground="#FF0000", font=("Arial", 14, "bold"))
result_text.tag_configure("safe", foreground="#008000", font=("Arial", 14, "bold"))
result_text.tag_configure("header", font=("Arial", 14, "bold"), foreground="#0057B8")
result_text.tag_configure("error", foreground="#FF0000", font=("Arial", 12))
result_text.tag_configure("suspicious", foreground="#FF4500", font=("Arial", 12))

# Start the GUI
root.mainloop()
