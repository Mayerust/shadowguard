import json
import time
import warnings
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split, StratifiedKFold, cross_validate, GridSearchCV
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import GaussianNB
from sklearn.svm import SVC
from xgboost import XGBClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, roc_auc_score, ConfusionMatrixDisplay,
    classification_report,
)
import joblib

warnings.filterwarnings("ignore")

print("=" * 65)
print("Model Training Module")
print("=" * 65)



#Load Data
print("\n Loading balanced dataset")
df = pd.read_csv("data/processed/features_balanced.csv")
df_raw = pd.read_csv("data/processed/features_raw.csv")  # for multi-class
with open("models/feature_columns.json") as f:
    feature_cols = json.load(f)

X = df[feature_cols].fillna(0)
y = df["is_malicious"]
print(f"       Samples: {len(X):,}  |  Features: {len(feature_cols)}")
print(f"       Class balance: {dict(y.value_counts())}")

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)



#Model Definitions: class_weight + tuned XGBoost
models = {
    "Logistic Regression": Pipeline([
        ("scaler", StandardScaler()),
        ("clf", LogisticRegression(
            max_iter=1000, class_weight="balanced", random_state=42,
        )),
    ]),
    "Naive Bayes": Pipeline([
        ("scaler", StandardScaler()),
        ("clf", GaussianNB()),
    ]),
    "SVM (RBF)": Pipeline([
        ("scaler", StandardScaler()),
        ("clf", SVC(
            kernel="rbf", probability=True,
            class_weight="balanced", random_state=42,
        )),
    ]),
    "Random Forest": Pipeline([
        ("clf", RandomForestClassifier(
            n_estimators=200, class_weight="balanced",
            random_state=42, n_jobs=-1,
        )),
    ]),
    "XGBoost": Pipeline([
        ("clf", XGBClassifier(
            n_estimators=300, learning_rate=0.05, max_depth=8,
            subsample=0.8, colsample_bytree=0.8,
            scale_pos_weight=1,
            use_label_encoder=False, eval_metric="logloss",
            random_state=42, n_jobs=-1,
        )),
    ]),
}




#5 Fold Cross-Validation
print("\n 5 fold cross-validation on all models")
skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
cv_results = {}

for name, pipe in models.items():
    t0 = time.time()
    scores = cross_validate(
        pipe, X_train, y_train, cv=skf,
        scoring=["accuracy", "precision", "recall", "f1", "roc_auc"],
        n_jobs=-1,
    )
    elapsed = time.time() - t0
    cv_results[name] = {
        "accuracy":  scores["test_accuracy"].mean(),
        "precision": scores["test_precision"].mean(),
        "recall":    scores["test_recall"].mean(),
        "f1":        scores["test_f1"].mean(),
        "roc_auc":   scores["test_roc_auc"].mean(),
        "std_f1":    scores["test_f1"].std(),
        "time_s":    elapsed,
    }
    r = cv_results[name]
    print(f"\n   {name}")
    print(f"     Acc={r['accuracy']:.4f}  Prec={r['precision']:.4f}  "
          f"Rec={r['recall']:.4f}  F1={r['f1']:.4f}±{r['std_f1']:.4f}  "
          f"AUC={r['roc_auc']:.4f}  [{elapsed:.1f}s]")

#Pick Winner
best_name = max(cv_results, key=lambda n: cv_results[n]["f1"])
best_pipe  = models[best_name]
print(f"\n[3/7] Winner: {best_name}  (CV F1 = {cv_results[best_name]['f1']:.4f})")




#GridSearchCV Tuning
print(f"\n Hyperparameter tuning ({best_name})")
param_grids = {
    "Random Forest": {
        "clf__n_estimators": [200, 300],
        "clf__max_depth":    [None, 10, 20],
        "clf__min_samples_split": [2, 5],
    },
    "XGBoost": {
        "clf__n_estimators":  [200, 300],
        "clf__max_depth":     [6, 8],
        "clf__learning_rate": [0.05, 0.1],
        "clf__subsample":     [0.8, 1.0],
    },
    "Logistic Regression": {
        "clf__C": [0.01, 0.1, 1.0, 10.0],
        "clf__solver": ["lbfgs", "saga"],
    },
    "Naive Bayes": {"clf__var_smoothing": [1e-9, 1e-7, 1e-5]},
    "SVM (RBF)": {
        "clf__C": [0.1, 1.0, 10.0],
        "clf__gamma": ["scale", "auto"],
    },
}

param_grid = param_grids.get(best_name, {})
if param_grid:
    gs = GridSearchCV(best_pipe, param_grid, cv=skf, scoring="f1", n_jobs=-1)
    gs.fit(X_train, y_train)
    final_model = gs.best_estimator_
    print(f"       Best params: {gs.best_params_}")
    print(f"       Best CV F1:  {gs.best_score_:.4f}")
else:
    best_pipe.fit(X_train, y_train)
    final_model = best_pipe




#Threshold Tuning
print("\n Threshold tuning")
THRESHOLD = 0.60   # lower = more aggressive blocking (fewer false negatives)
y_proba  = final_model.predict_proba(X_test)[:, 1]
y_pred   = (y_proba > THRESHOLD).astype(int)

metrics = {
    "accuracy":  round(accuracy_score(y_test, y_pred),  4),
    "precision": round(precision_score(y_test, y_pred), 4),
    "recall":    round(recall_score(y_test, y_pred),    4),
    "f1":        round(f1_score(y_test, y_pred),        4),
    "roc_auc":   round(roc_auc_score(y_test, y_proba),  4),
}
cm = confusion_matrix(y_test, y_pred)
print(f"\n   Final metrics at threshold = {THRESHOLD}")
print(f"   {'─'*40}")
for k, v in metrics.items():
    bar = "█" * int(v * 30)
    print(f"   {k:<12}: {v:.4f}  {bar}")
print(f"\n   Confusion Matrix:")
print(f"   TN={cm[0,0]:>5}  FP={cm[0,1]:>5}")
print(f"   FN={cm[1,0]:>5}  TP={cm[1,1]:>5}")




#Feature Importance
print("\n Feature importance analysis")
clf_step = final_model.named_steps.get("clf")
importances = getattr(clf_step, "feature_importances_", None)
top_features = []
if importances is not None:
    ranked = sorted(zip(feature_cols, importances), key=lambda x: x[1], reverse=True)
    top_features = [(name, round(float(val), 6)) for name, val in ranked[:20]]
    print("\n   Top 15 Features:")
    for feat, imp in top_features[:15]:
        bar = "█" * int(imp * 400)
        print(f"   {feat:<28}: {imp:.4f}  {bar}")




#UPGRADE: Fast Inference Mode
if hasattr(clf_step, "n_jobs"):
    clf_step.n_jobs = 1   # single-thread for low-latency WAF inference



#Multi-class Attack Type Model
print("\n[7/7] Training multi-class attack-type classifier...")
df_mc = df_raw[df_raw["label"].isin(["normal","sqli","xss","path_traversal","cmd_injection","header_attack","attack"])].copy()
df_mc["label"] = df_mc["label"].replace("attack", "unknown_attack")

le = LabelEncoder()
df_mc["label_enc"] = le.fit_transform(df_mc["label"])

X_mc = df_mc[feature_cols].fillna(0)
y_mc = df_mc["label_enc"]
X_tr, X_te, y_tr, y_te = train_test_split(X_mc, y_mc, test_size=0.2, random_state=42, stratify=y_mc)

mc_model = RandomForestClassifier(
    n_estimators=200, class_weight="balanced", random_state=42, n_jobs=-1
)
mc_model.fit(X_tr, y_tr)
mc_pred = mc_model.predict(X_te)
mc_f1 = f1_score(y_te, mc_pred, average="weighted")
print(f"       Multi-class weighted F1: {mc_f1:.4f}")
print(f"       Classes: {list(le.classes_)}")
joblib.dump(mc_model, "models/attack_type_model.pkl")
joblib.dump(le, "models/label_encoder.pkl")




#Save Artifacts
joblib.dump(final_model, "models/shadowguard_model.pkl")

report = {
    "best_model":    best_name,
    "threshold":     THRESHOLD,
    "final_metrics": metrics,
    "confusion_matrix": cm.tolist(),
    "cv_results":    cv_results,
    "feature_columns": feature_cols,
    "top_features":  top_features,
    "attack_type_classes": list(le.classes_),
    "attack_type_f1": round(mc_f1, 4),
}
with open("models/training_report.json", "w") as f:
    json.dump(report, f, indent=2)







#Charts
fig, axes = plt.subplots(1, 3, figsize=(18, 5))
fig.suptitle(f"ShadowGuard v2 — {best_name} @ threshold {THRESHOLD}", fontsize=13, fontweight="bold")

ConfusionMatrixDisplay(cm, display_labels=["Normal","Attack"]).plot(ax=axes[0], colorbar=False, cmap="Blues")
axes[0].set_title("Confusion Matrix")

names = list(cv_results.keys())
f1s   = [cv_results[n]["f1"] for n in names]
colors= ["#ef4444" if n == best_name else "#64748b" for n in names]
axes[1].barh(names, f1s, color=colors)
axes[1].set_xlim(0, 1); axes[1].set_xlabel("F1 Score"); axes[1].set_title("Model Comparison")
for i, v in enumerate(f1s):
    axes[1].text(v + 0.01, i, f"{v:.4f}", va="center", fontsize=9)

if top_features:
    feat_names = [x[0] for x in top_features[:12]]
    feat_vals  = [x[1] for x in top_features[:12]]
    axes[2].barh(feat_names[::-1], feat_vals[::-1], color="#4f8ef7")
    axes[2].set_title("Top Feature Importances")

plt.tight_layout()
plt.savefig("models/training_report.png", dpi=150, bbox_inches="tight")

print(f"\n{'='*65}")
print("Done!")
print(f"  Binary model:    models/shadowguard_model.pkl  (F1={metrics['f1']})")
print(f"  Type classifier: models/attack_type_model.pkl  (F1={mc_f1:.4f})")
print(f"  Threshold:       {THRESHOLD}")
print(f"  Report:          models/training_report.json")
print(f"  Charts:          models/training_report.png")
print(f"{'='*65}")