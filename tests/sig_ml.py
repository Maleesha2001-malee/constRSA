# sig_ml.py — RSA Signature Verification ML Model
# =================================================
# What this does:
#   1. Load signature dataset (valid + invalid)
#   2. Train ML classifier
#   3. Verify signatures automatically
#   4. Report accuracy

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (accuracy_score, precision_score,
                              recall_score, f1_score,
                              confusion_matrix, classification_report)
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

print("=" * 50)
print("  ConstRSA — ML Signature Verifier")
print("=" * 50)

# ══ Step 1: Load Data ══
print("\n[1] Loading signature dataset...")
df = pd.read_csv("data\\sig_dataset.csv")

# RSA public key (same as generator)
n = 999983 * 999979
e = 65537
print(f"    Total rows : {len(df)}")
print(f"    Valid (1)  : {(df['label']==1).sum()}")
print(f"    Invalid (0): {(df['label']==0).sum()}")
print(df.head(5))

# ══ Step 2: Feature Engineering ══
# Features: msg_hash සහ signature values
# ML model ට ඉගෙන ගන්නා pattern:
#   valid sig   → msg_hash සහ sig mathematically related
#   invalid sig → random, no relation

df["hash_mod_sig"] = df["msg_hash"] % (df["signature"] + 1)
df["sig_mod_hash"] = df["signature"] % (df["msg_hash"] + 1)
df["ratio"]        = df["msg_hash"] / (df["signature"] + 1)
df["diff"]         = abs(df["msg_hash"] - df["signature"])

X = df[["hash_matches", "sig_in_range"]].values
y = df["label"].values

print(f"\n[2] Features : {X.shape[1]}")
print(f"    Samples  : {X.shape[0]}")

# ══ Step 3: Train/Test Split ══
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y)

print(f"\n[3] Train size: {len(X_train)}")
print(f"    Test size : {len(X_test)}")

# ══ Step 4: Train Model ══
print("\n[4] Training Random Forest...")
clf = RandomForestClassifier(
    n_estimators=100,
    max_depth=15,
    random_state=42,
    n_jobs=-1
)
clf.fit(X_train, y_train)
print("    Training complete!")

# ══ Step 5: Evaluate ══
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
print(f"  {'':15s} Pred Invalid  Pred Valid")
print(f"  {'Actual Invalid':15s} {cm[0][0]:^12d} {cm[0][1]:^10d}")
print(f"  {'Actual Valid':15s} {cm[1][0]:^12d} {cm[1][1]:^10d}")

print("\n  Classification Report:")
print(classification_report(y_test, y_pred,
      target_names=["Invalid", "Valid"]))

# ══ Step 6: Test with new signatures ══
print("=" * 50)
print("  LIVE SIGNATURE VERIFICATION TEST")
print("=" * 50)

# Test samples — manually created
test_samples = [
    # [msg_hash, signature] from our dataset (valid)
    [df[df["label"]==1].iloc[0]["msg_hash"],
     df[df["label"]==1].iloc[0]["signature"], "VALID"],
    [df[df["label"]==1].iloc[1]["msg_hash"],
     df[df["label"]==1].iloc[1]["signature"], "VALID"],
    # invalid samples
    [df[df["label"]==0].iloc[0]["msg_hash"],
     df[df["label"]==0].iloc[0]["signature"], "INVALID"],
    [df[df["label"]==0].iloc[1]["msg_hash"],
     df[df["label"]==0].iloc[1]["signature"], "INVALID"],
]

print(f"\n  {'#':<3} {'Expected':<10} {'ML Says':<10} {'Correct?'}")
print(f"  {'-'*40}")
for idx, (h, s, expected) in enumerate(test_samples):
    # hash_matches: recovered == msg_hash?
    hash_matches = 1 if pow(int(s), e, n) == int(h) else 0
    sig_in_range = 1 if s < n else 0
    feat = np.array([[hash_matches, sig_in_range]])
# ══ Step 7: Save results ══
results = pd.DataFrame({
    "metric": ["Accuracy","Precision","Recall","F1"],
    "value":  [acc, prec, rec, f1]
})
results.to_csv("data\\sig_ml_results.csv", index=False)

# ══ Step 8: Plot ══
fig, axes = plt.subplots(1, 2, figsize=(12, 5))
fig.suptitle("ConstRSA — ML Signature Verification", fontsize=13)

# Confusion matrix
im = axes[0].imshow(cm, cmap=plt.cm.Blues)
axes[0].set_title("Confusion Matrix")
axes[0].set_xticks([0,1])
axes[0].set_yticks([0,1])
axes[0].set_xticklabels(["Invalid","Valid"])
axes[0].set_yticklabels(["Invalid","Valid"])
axes[0].set_xlabel("Predicted")
axes[0].set_ylabel("Actual")
for i in range(2):
    for j in range(2):
        axes[0].text(j, i, str(cm[i][j]),
                    ha="center", va="center",
                    color="white" if cm[i][j]>cm.max()/2
                    else "black", fontsize=14)

# Metrics bar chart
metrics = ["Accuracy","Precision","Recall","F1"]
values  = [acc*100, prec*100, rec*100, f1*100]
bars = axes[1].bar(metrics, values, color="steelblue")
axes[1].set_ylim([90, 101])
axes[1].set_title("Model Performance")
axes[1].set_ylabel("Score (%)")
for bar, val in zip(bars, values):
    axes[1].text(bar.get_x() + bar.get_width()/2,
                bar.get_height() + 0.1,
                f"{val:.1f}%", ha="center", fontsize=10)

plt.tight_layout()
plt.savefig("docs\\sig_ml_chart.png", dpi=150)
print(f"\n  Chart saved : docs\\sig_ml_chart.png")
print(f"  Results saved: data\\sig_ml_results.csv")
print("=" * 50)