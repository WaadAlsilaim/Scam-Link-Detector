import json
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, roc_auc_score
from xgboost import XGBClassifier
import joblib

from features import extract_features, FEATURE_NAMES

df = pd.read_csv("data/urls_labeled.csv")
print(f"Loaded {len(df)} rows")

feat_rows = [extract_features(u) for u in df["url"]]
X = pd.DataFrame(feat_rows)[FEATURE_NAMES]
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

results = {}

rf = RandomForestClassifier(n_estimators=300, max_depth=12, random_state=42, n_jobs=-1)
rf.fit(X_train, y_train)
rf_pred = rf.predict(X_test)
rf_proba = rf.predict_proba(X_test)[:, 1]
results["random_forest"] = {
    "report": classification_report(y_test, rf_pred, output_dict=True),
    "roc_auc": roc_auc_score(y_test, rf_proba),
}

xgb = XGBClassifier(
    n_estimators=300, max_depth=6, learning_rate=0.1,
    eval_metric="logloss", random_state=42, n_jobs=-1
)
xgb.fit(X_train, y_train)
xgb_pred = xgb.predict(X_test)
xgb_proba = xgb.predict_proba(X_test)[:, 1]
results["xgboost"] = {
    "report": classification_report(y_test, xgb_pred, output_dict=True),
    "roc_auc": roc_auc_score(y_test, xgb_proba),
}

for name, res in results.items():
    r = res["report"]
    print(f"\n{name}")
    print(f"  accuracy: {r['accuracy']:.3f}")
    print(f"  phishing precision/recall: {r['1']['precision']:.3f} / {r['1']['recall']:.3f}")
    print(f"  roc_auc: {res['roc_auc']:.3f}")

# Pick the better model by ROC-AUC (ties broken toward XGBoost for speed+size)
best_name = "xgboost" if results["xgboost"]["roc_auc"] >= results["random_forest"]["roc_auc"] else "random_forest"
best_model = xgb if best_name == "xgboost" else rf
print(f"\nSelected model: {best_name}")

joblib.dump(best_model, "models/model.joblib")
with open("models/feature_names.json", "w") as f:
    json.dump(FEATURE_NAMES, f)
with open("models/metrics.json", "w") as f:
    json.dump({k: {"roc_auc": v["roc_auc"], "accuracy": v["report"]["accuracy"]} for k, v in results.items()}, f, indent=2)

importances = sorted(zip(FEATURE_NAMES, best_model.feature_importances_), key=lambda x: -x[1])
print("\nTop 10 features:")
for name, imp in importances[:10]:
    print(f"  {name}: {imp:.4f}")
