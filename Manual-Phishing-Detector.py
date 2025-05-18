import pandas as pd
from urllib.parse import urlparse
import time
import os

# Configuration
INPUT_FILE = "Dataset549k.csv"
OUTPUT_FILE = "phishing_results_full_verified.csv"
CHUNK_SIZE = 50000  # Process 50k URLs at a time

# Initialize timers
total_start = time.time()
stats = {
    'total': 0,
    'correct': 0,
    'false_positives': 0,
    'false_negatives': 0
}

try:
    # Prepare output file with all required columns
    pd.DataFrame(columns=[
        'url', 'label', 'has_ip', 'long_url', 'uses_https', 
        'has_at_symbol', 'suspicious_words', 'suspicious_tld',
        'final_verdict', 'verification_status'
    ]).to_csv(OUTPUT_FILE, index=False)

    # Process in chunks
    for chunk_idx, df_chunk in enumerate(pd.read_csv(INPUT_FILE, chunksize=CHUNK_SIZE)):
        chunk_start = time.time()
        
        # Verify required columns exist
        url_col = next((col for col in df_chunk.columns if col.lower() in ['url', 'website', 'link']), None)
        label_col = next((col for col in df_chunk.columns if col.lower() in ['label', 'phish', 'status']), None)
        
        if not url_col or not label_col:
            raise KeyError(f"Missing required columns in chunk {chunk_idx}")

        df_chunk = df_chunk.rename(columns={
            url_col: 'url',
            label_col: 'label'
        })

        # Feature extraction with timing
        def analyze_url(row):
            start_time = time.time()
            url = row['url']
            label = int(row['label'])  # Ensure label is 0/1
            
            try:
                parsed = urlparse(url)
                domain = parsed.netloc.lower()
                tld = domain.split('.')[-1]
                
                # Extract features
                features = {
                    'has_ip': int(any(seg.isdigit() for seg in domain.split('.'))),
                    'long_url': int(len(url) > 75),
                    'uses_https': int(parsed.scheme == 'https'),
                    'has_at_symbol': int('@' in url),
                    'suspicious_words': int(any(word in domain for word in ['secure', 'login', 'verify'])),
                    'suspicious_tld': int(tld in ['tk', 'xyz', 'gq', 'ml']),
                }
                
                # Calculate final verdict (at least one suspicious feature)
                final_verdict = int(any(features.values()))
                
                # Verification
                verification = 'OK' if label == final_verdict else \
                              'FP' if (final_verdict == 1 and label == 0) else \
                              'FN'  # false negative
                
                # Update statistics
                stats['total'] += 1
                if verification == 'OK':
                    stats['correct'] += 1
                elif verification == 'FP':
                    stats['false_positives'] += 1
                else:
                    stats['false_negatives'] += 1
                    
            except Exception as e:
                features = {k: 0 for k in ['has_ip', 'long_url', 'uses_https', 
                                          'has_at_symbol', 'suspicious_words', 'suspicious_tld']}
                final_verdict = 0
                verification = 'ERROR'
                
            elapsed_ms = (time.time() - start_time) * 1000
            
            return pd.Series({
                **features,
                'final_verdict': final_verdict,
                'verification_status': verification,
                'processing_time_ms': elapsed_ms
            })

        # Process current chunk
        print(f"\n🔍 Processing chunk {chunk_idx+1} ({len(df_chunk)} URLs)...")
        results = df_chunk.join(df_chunk.apply(analyze_url, axis=1))
        
        # Append to output
        results.to_csv(OUTPUT_FILE, mode='a', header=False, index=False)
        
        # Progress update
        chunk_time = time.time() - chunk_start
        print(f"✅ Chunk completed in {chunk_time:.2f}s")
        print(f"↳ Current stats: {stats['correct']/stats['total']:.2%} accuracy")

    # Final report
    total_time = time.time() - total_start
    print("\n📊 Final Report")
    print(f"Total URLs processed: {stats['total']:,}")
    print(f"Total time: {total_time:.2f} seconds")
    print(f"Processing speed: {stats['total']/total_time:,.0f} URLs/sec")
    print(f"\nAccuracy: {stats['correct']/stats['total']:.2%}")
    print(f"False Positives: {stats['false_positives']:,} ({stats['false_positives']/stats['total']:.2%})")
    print(f"False Negatives: {stats['false_negatives']:,} ({stats['false_negatives']/stats['total']:.2%})")
    
    # Sample output verification
    sample = pd.read_csv(OUTPUT_FILE, nrows=5)
    print("\nSample output:")
    print(sample[['url', 'label', 'final_verdict', 'verification_status']])

except Exception as e:
    print(f"\n❌ Processing failed: {str(e)}")
    print(f"Last successful chunk: {chunk_idx}")
    if 'results' in locals():
        print(f"Last processed URL: {results.iloc[-1]['url']}")
