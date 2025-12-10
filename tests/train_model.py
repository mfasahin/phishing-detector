# train_model.py - ML Model Eğitim Script'i

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import joblib
import os

print("="*60)
print("🤖 PHISHING DETECTION ML MODEL TRAINING")
print("="*60)

# 1. Dataset'i Yükle
print("\n📂 Loading dataset...")
try:
    # Farklı dosya isimlerini dene
    if os.path.exists('data/phishing_data.csv'):
        df = pd.read_csv('data/phishing_data.csv')
    elif os.path.exists('data/dataset_phishing.csv'):
        df = pd.read_csv('data/dataset_phishing.csv')
    elif os.path.exists('data/phishing.csv'):
        df = pd.read_csv('data/phishing.csv')
    else:
        # data klasöründeki ilk CSV dosyasını al
        csv_files = [f for f in os.listdir('data') if f.endswith('.csv')]
        if csv_files:
            df = pd.read_csv(f'data/{csv_files[0]}')
            print(f"✅ Found dataset: {csv_files[0]}")
        else:
            raise FileNotFoundError("No CSV file found in data/ directory")
    
    print(f"✅ Dataset loaded successfully!")
    print(f"📊 Shape: {df.shape}")
    print(f"📋 Columns: {df.columns.tolist()}")
    
except Exception as e:
    print(f"❌ Error loading dataset: {e}")
    print("\n💡 Tip: Make sure your CSV file is in the 'data/' folder")
    exit(1)

# 2. Dataset'i İncele
print("\n" + "="*60)
print("📊 DATASET EXPLORATION")
print("="*60)

print("\nFirst 5 rows:")
print(df.head())

print("\nDataset info:")
print(df.info())

print("\nBasic statistics:")
print(df.describe())

# Label sütununu bul (phishing, label, class, target, vb.)
possible_label_names = ['label', 'class', 'target', 'phishing', 'status', 'Label', 'Class']
label_column = None

for col in possible_label_names:
    if col in df.columns:
        label_column = col
        break

if label_column is None:
    print("\n❌ Could not find label column!")
    print(f"Available columns: {df.columns.tolist()}")
    print("\n💡 Please check your dataset and update the script")
    exit(1)

print(f"\n✅ Label column found: '{label_column}'")
print(f"Label distribution:\n{df[label_column].value_counts()}")

# 3. Features ve Target'ı Ayır
print("\n" + "="*60)
print("🔧 PREPARING DATA")
print("="*60)

# Label sütununu target olarak al, geri kalanı features
X = df.drop(label_column, axis=1)
y = df[label_column]

# Label'ları 0 ve 1'e dönüştür (eğer değilse)
if y.dtype == 'object' or set(y.unique()) != {0, 1}:
    print(f"Converting labels to 0 and 1...")
    # Phishing = 1, Legitimate = 0
    label_mapping = {}
    unique_labels = y.unique()
    
    # Otomatik mapping
    for i, label in enumerate(unique_labels):
        if isinstance(label, str):
            if 'phish' in label.lower() or 'bad' in label.lower() or '1' in str(label):
                label_mapping[label] = 1
            else:
                label_mapping[label] = 0
        else:
            label_mapping[label] = int(label)
    
    y = y.map(label_mapping)
    print(f"Label mapping: {label_mapping}")

print(f"✅ Features shape: {X.shape}")
print(f"✅ Target shape: {y.shape}")
print(f"Features: {X.columns.tolist()}")

# Kategorik değişkenleri sayısal hale getir
if X.select_dtypes(include=['object']).shape[1] > 0:
    print("\n🔄 Converting categorical features to numerical...")
    X = pd.get_dummies(X, drop_first=True)
    print(f"✅ New feature count: {X.shape[1]}")

# 4. Train/Test Split
print("\n" + "="*60)
print("✂️ SPLITTING DATA")
print("="*60)

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print(f"✅ Training set: {X_train.shape[0]} samples")
print(f"✅ Testing set: {X_test.shape[0]} samples")
print(f"Training label distribution:\n{y_train.value_counts()}")

# 5. Model Oluştur ve Eğit
print("\n" + "="*60)
print("🤖 TRAINING MODEL")
print("="*60)

print("\n🌲 Using Random Forest Classifier...")
model = RandomForestClassifier(
    n_estimators=100,
    max_depth=20,
    random_state=42,
    n_jobs=-1,  # Tüm CPU'ları kullan
    verbose=1
)

print("Training started...")
model.fit(X_train, y_train)
print("✅ Training completed!")

# 6. Model Değerlendirmesi
print("\n" + "="*60)
print("📈 MODEL EVALUATION")
print("="*60)

# Predictions
y_pred = model.predict(X_test)

# Accuracy
accuracy = accuracy_score(y_test, y_pred)
print(f"\n🎯 Accuracy: {accuracy*100:.2f}%")

# Classification Report
print("\n📊 Classification Report:")
print(classification_report(y_test, y_pred, 
                          target_names=['Legitimate', 'Phishing']))

# Confusion Matrix
print("🔢 Confusion Matrix:")
cm = confusion_matrix(y_test, y_pred)
print(cm)
print("\nInterpretation:")
print(f"  True Negatives (Legitimate correctly identified): {cm[0][0]}")
print(f"  False Positives (Legitimate marked as Phishing): {cm[0][1]}")
print(f"  False Negatives (Phishing marked as Legitimate): {cm[1][0]}")
print(f"  True Positives (Phishing correctly identified): {cm[1][1]}")

# Feature Importance
print("\n🔝 Top 10 Most Important Features:")
feature_importance = pd.DataFrame({
    'feature': X.columns,
    'importance': model.feature_importances_
}).sort_values('importance', ascending=False)

print(feature_importance.head(10))

# 7. Model'i Kaydet
print("\n" + "="*60)
print("💾 SAVING MODEL")
print("="*60)

# Model'i kaydet
model_path = 'data/phishing_model.pkl'
joblib.dump(model, model_path)
print(f"✅ Model saved to: {model_path}")

# Feature names'i de kaydet (inference sırasında gerekli)
feature_names_path = 'data/feature_names.pkl'
joblib.dump(X.columns.tolist(), feature_names_path)
print(f"✅ Feature names saved to: {feature_names_path}")

# 8. Test Predictions
print("\n" + "="*60)
print("🧪 SAMPLE PREDICTIONS")
print("="*60)

# Rastgele 5 örnek al
sample_indices = np.random.choice(X_test.index, 5, replace=False)
samples = X_test.loc[sample_indices]
sample_labels = y_test.loc[sample_indices]

predictions = model.predict(samples)
probabilities = model.predict_proba(samples)

for i, idx in enumerate(sample_indices):
    actual = "Phishing" if sample_labels.iloc[i] == 1 else "Legitimate"
    predicted = "Phishing" if predictions[i] == 1 else "Legitimate"
    confidence = probabilities[i][predictions[i]] * 100
    
    status = "✅" if sample_labels.iloc[i] == predictions[i] else "❌"
    print(f"\n{status} Sample {i+1}:")
    print(f"  Actual: {actual}")
    print(f"  Predicted: {predicted} (Confidence: {confidence:.2f}%)")

# 9. Model Özeti
print("\n" + "="*60)
print("📝 MODEL SUMMARY")
print("="*60)

print(f"""
Model Type: Random Forest Classifier
Training Samples: {X_train.shape[0]}
Testing Samples: {X_test.shape[0]}
Number of Features: {X.shape[1]}
Number of Trees: 100
Accuracy: {accuracy*100:.2f}%

Model saved to: {model_path}
Feature names saved to: {feature_names_path}

✅ Model is ready to be integrated into the API!
""")

print("="*60)
print("🎉 TRAINING COMPLETED SUCCESSFULLY!")
print("="*60)