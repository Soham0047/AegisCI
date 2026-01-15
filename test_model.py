#!/usr/bin/env python3
"""Test the trained model predictions."""

import torch
import re
from ml.models.transformer import build_model, SimpleVocab

# Load checkpoint
checkpoint = torch.load('artifacts/dl/transformer_enhanced.pt', map_location='cpu', weights_only=False)
print('Temperature:', checkpoint.get('temperature_risk', 1.0))

# Rebuild model
vocab_data = checkpoint['vocab']
# vocab_data is the token_to_id dict directly (from train_transformer.py)
# or has 'token_to_id' key (from train_pipeline.py)
if 'token_to_id' in vocab_data:
    token_to_id = vocab_data['token_to_id']
    id_to_token = vocab_data.get('id_to_token', list(token_to_id.keys()))
else:
    # Direct token_to_id dict
    token_to_id = vocab_data
    id_to_token = list(token_to_id.keys())

# Reconstruct SimpleVocab
vocab = SimpleVocab(token_to_id=token_to_id, id_to_token=id_to_token)
vocab_size = len(token_to_id)
category_vocab = checkpoint['category_vocab']
max_len = checkpoint['max_len']

print(f'Vocab size: {vocab_size}, Categories: {len(category_vocab)}')

model = build_model(
    model_name='small',
    num_categories=len(category_vocab),
    vocab_size=vocab_size,
    max_len=max_len,
    random_init=True,
)
model.load_state_dict(checkpoint['model_state_dict'])
model.eval()

# Test cases
test_cases = [
    ('Safe code', 'def add(a, b): return a + b'),
    ('SQL injection', 'query = SELECT FROM users WHERE id + user_id'),
    ('Shell command', 'subprocess.call(user_input, shell=True)'),
    ('Hardcoded secret', 'API_KEY = sk-1234567890abcdef'),
    ('Simple print', 'print(Hello World)'),
    ('File read', 'with open(filename) as f: data = f.read()'),
    ('Loop', 'for i in range(10): print(i)'),
    ('Eval', 'result = eval(user_code)'),
    ('Exec', 'exec(user_input)'),
    ('Pickle load', 'data = pickle.loads(user_data)'),
]

temperature = checkpoint.get('temperature_risk', 1.0)

print("\nModel predictions:")
print("-" * 50)
for name, code in test_cases:
    tokens = re.findall(r'[a-zA-Z_][a-zA-Z0-9_]*|[0-9]+|[^\s\w]', code)
    token_ids, attention = vocab.encode(tokens, max_len)
    input_ids = torch.tensor([token_ids], dtype=torch.long)
    attention_mask = torch.tensor([attention], dtype=torch.long)
    
    with torch.no_grad():
        cat_logits, risk_logit = model(input_ids=input_ids, attention_mask=attention_mask)
        raw_score = torch.sigmoid(risk_logit / temperature).item()
        
        # Get best category
        cat_probs = torch.sigmoid(cat_logits).squeeze(0)
        best_cat_idx = cat_probs.argmax().item()
        best_cat = category_vocab[best_cat_idx]
        best_cat_score = cat_probs[best_cat_idx].item()
        
    risk_label = "HIGH" if raw_score >= 0.7 else "MED" if raw_score >= 0.4 else "LOW"
    print(f'{name:20s}: risk={raw_score:.4f} ({risk_label}) category={best_cat}')
