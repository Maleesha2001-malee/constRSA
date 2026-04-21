# ml_analysis.py — ConstRSA Timing Leak Detection using ML
# =========================================================
# What this does:
#   1. Load timing data (CSV)
#   2. Train ML classifier (Random Forest)
#   3. Detect timing leak — CT vs Naive
#   4. Report Accuracy, Precision, Recall, F1
#   5. Save results to data/ml_results.csv
#   6. Plot confusion matrix and feature importance

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (accuracy_score, precision_score,
                              recall_score, f1_score,
                              confusion_matrix, classification_report)
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')  # Windows compatible

print("=" * 50)
print("  ConstRSA — ML Timing Leak Detector")
print("=" * 50)

# ══ Step 1: Load Data ══
print("\n[1] Loading timing data...")
df = pd.read_csv("data\\timing_data.csv")
print(f"    Total rows: {len(df)}")
print(df.head(5))

# ══ Step 2: Remove outliers (top 1%) ══
df = df[df["time_ns"] < df["time_ns"].quantile(0.99)]
print(f"    After outlier removal: {len(df)} rows")

# ══ Step 3: Feature Engineering ══
# Label: 1 = naive (leaks), 0 = constant-time (safe)
df["label"] = (df["implementation"] == "naive").astype(int)

# Features: timing value + input type encoded
df["input_encoded"] = (df["input_type"] == "random").astype(int)

# Add more features for better accuracy
df["time_log"] = np.log1p(df["time_ns"])
df["time_sq"]  = df["time_ns"] ** 2

X = df[["time_ns", "input_encoded", "time_log", "time_sq"]].values
y = df["label"].values

print(f"\n[2] Features: {X.shape[1]}")
print(f"    Samples : {X.shape[0]}")
print(f"    CT (0)  : {(y==0).sum()}")
print(f"    Naive(1): {(y==1).sum()}")

# ══ Step 4: Train/Test Split ══
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y)

print(f"\n[3] Train size: {len(X_train)}")
print(f"    Test size : {len(X_test)}")

# ══ Step 5: Train Random Forest ══
print("\n[4] Training Random Forest classifier...")
clf = RandomForestClassifier(
    n_estimators=100,
    max_depth=10,
    random_state=42,
    n_jobs=-1
)
clf.fit(X_train, y_train)
print("    Training complete!")

# ══ Step 6: Evaluate ══
y_pred = clf.predict(X_test)

acc  = accuracy_score(y_test, y_pred)
prec = precision_score(y_test, y_pred)
rec  = recall_score(y_test, y_pred)
f1   = f1_score(y_test, y_pred)
cm   = confusion_matrix(y_test, y_pred)

print("\n" + "=" * 50)
print("  RESULTS")
print("=" * 50)
print(f"\n  Accuracy  : {acc*100:.2f}%")
print(f"  Precision : {prec*100:.2f}%")
print(f"  Recall    : {rec*100:.2f}%")
print(f"  F1 Score  : {f1*100:.2f}%")

print("\n  Confusion Matrix:")
print(f"  {'':15s} Predicted CT  Predicted Naive")
print(f"  {'Actual CT':15s} {cm[0][0]:^13d} {cm[0][1]:^15d}")
print(f"  {'Actual Naive':15s} {cm[1][0]:^13d} {cm[1][1]:^15d}")

print("\n  Classification Report:")
print(classification_report(y_test, y_pred,
      target_names=["Constant-time", "Naive"]))

# ══ Step 7: Interpretation ══
print("=" * 50)
print("  TIMING LEAK INTERPRETATION")
print("=" * 50)
if acc >= 0.95:
    print(f"\n  Naive implementation : TIMING LEAK DETECTED")
    print(f"  ML can distinguish CT vs Naive with {acc*100:.1f}% accuracy")
    print(f"  This confirms secret-dependent timing differences exist")
else:
    print(f"\n  Low accuracy ({acc*100:.1f}%) — timing patterns unclear")

print(f"\n  Feature Importance:")
features = ["time_ns", "input_encoded", "time_log", "time_sq"]
importances = clf.feature_importances_
for f, imp in zip(features, importances):
    print(f"    {f:15s} : {imp*100:.1f}%")

# ══ Step 8: Save Results ══
results_df = pd.DataFrame({
    "metric": ["Accuracy", "Precision", "Recall", "F1"],
    "value":  [acc, prec, rec, f1]
})
results_df.to_csv("data\\ml_results.csv", index=False)
print("\n  Results saved: data\\ml_results.csv")

# ══ Step 9: Plots ══
fig, axes = plt.subplots(1, 2, figsize=(12, 5))
fig.suptitle("ConstRSA — ML Timing Leak Detection", fontsize=13)

# Confusion Matrix
im = axes[0].imshow(cm, interpolation='nearest', cmap=plt.cm.Blues)
axes[0].set_title("Confusion Matrix")
axes[0].set_xlabel("Predicted")
axes[0].set_ylabel("Actual")
axes[0].set_xticks([0, 1])
axes[0].set_yticks([0, 1])
axes[0].set_xticklabels(["CT (safe)", "Naive (leak)"])
axes[0].set_yticklabels(["CT (safe)", "Naive (leak)"])
for i in range(2):
    for j in range(2):
        axes[0].text(j, i, str(cm[i][j]),
                     ha="center", va="center",
                     color="white" if cm[i][j] > cm.max()/2
                     else "black", fontsize=14)

# Feature Importance
axes[1].bar(features, importances * 100, color="steelblue")
axes[1].set_title("Feature Importance")
axes[1].set_xlabel("Feature")
axes[1].set_ylabel("Importance (%)")
axes[1].tick_params(axis='x', rotation=15)

plt.tight_layout()
plt.savefig("docs\\ml_chart.png", dpi=150)
print("  Chart saved : docs\\ml_chart.png")
print("=" * 50)