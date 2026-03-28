import json
import time
import warnings
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import (
    train_test_split, StratifiedKFold, cross_validate, GridSearchCV
)
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import GaussianNB
from sklearn.svm import SVC
from xgboost import XGBClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, confusion_matrix, roc_auc_score,
    ConfusionMatrixDisplay, RocCurveDisplay
)
import joblib

warnings.filterwarnings("ignore")


print("Model Training Module")


#Load Data
print("\n Loading balanced dataset...")
df = pd.read_csv("data/processed/features_balanced.csv")
with open("models/feature_columns.json") as f:
    feature_cols = json.load(f)

X = df[feature_cols].fillna(0)
y = df["is_malicious"]
print(f"       Samples: {len(X):,} | Features: {len(feature_cols)}")
print(f"       Class balance: {dict(y.value_counts())}")

#Train / Test Split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

#Model Definitions
models = {
    "Logistic Regression": Pipeline([
        ("scaler", StandardScaler()),
        ("clf", LogisticRegression(max_iter=1000, random_state=42)),
    ]),
    "Naive Bayes": Pipeline([
        ("scaler", StandardScaler()),
        ("clf", GaussianNB()),
    ]),
    "SVM (RBF)": Pipeline([
        ("scaler", StandardScaler()),
        ("clf", SVC(kernel="rbf", probability=True, random_state=42)),
    ]),
    "Random Forest": Pipeline([
        ("clf", RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)),
    ]),
    "XGBoost": Pipeline([
        ("clf", XGBClassifier(
            n_estimators=200, learning_rate=0.1, max_depth=6,
            use_label_encoder=False, eval_metric="logloss",
            random_state=42, n_jobs=-1,
        )),
    ]),
}

#5-Fold Cross-Validation
print("\n Running 5-fold cross-validation on all models")
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
    print(f"     Accuracy={r['accuracy']:.4f} | Precision={r['precision']:.4f} | "
          f"Recall={r['recall']:.4f} | F1={r['f1']:.4f} ± {r['std_f1']:.4f} | "
          f"AUC={r['roc_auc']:.4f} | Time={elapsed:.1f}s")

#Select Best Model
best_name = max(cv_results, key=lambda n: cv_results[n]["f1"])
best_pipe = models[best_name]
print(f"\n Winner: {best_name} (F1 = {cv_results[best_name]['f1']:.4f})")

#Hyperparameter Tuning (GridSearchCV)
print(f"\n Tuning hyperparameters for {best_name}...")

param_grids = {
    "Random Forest": {
        "clf__n_estimators": [100, 200, 300],
        "clf__max_depth": [None, 10, 20],
        "clf__min_samples_split": [2, 5],
    },
    "XGBoost": {
        "clf__n_estimators": [100, 200],
        "clf__max_depth": [4, 6, 8],
        "clf__learning_rate": [0.05, 0.1, 0.2],
    },
    "Logistic Regression": {
        "clf__C": [0.01, 0.1, 1.0, 10.0],
        "clf__solver": ["lbfgs", "saga"],
    },
    "Naive Bayes": {
        "clf__var_smoothing": [1e-9, 1e-7, 1e-5],
    },
    "SVM (RBF)": {
        "clf__C": [0.1, 1.0, 10.0],
        "clf__gamma": ["scale", "auto"],
    },
}

param_grid = param_grids.get(best_name, {})
if param_grid:
    grid_search = GridSearchCV(
        best_pipe, param_grid, cv=skf, scoring="f1",
        n_jobs=-1, verbose=0,
    )
    grid_search.fit(X_train, y_train)
    final_model = grid_search.best_estimator_
    print(f"       Best params: {grid_search.best_params_}")
    print(f"       Best CV F1:  {grid_search.best_score_:.4f}")
else:
    best_pipe.fit(X_train, y_train)
    final_model = best_pipe

#Final Evaluation
print("\n Final evaluation on held-out test set")
y_pred = final_model.predict(X_test)
y_proba = final_model.predict_proba(X_test)[:, 1]

metrics = {
    "accuracy":  round(accuracy_score(y_test, y_pred), 4),
    "precision": round(precision_score(y_test, y_pred), 4),
    "recall":    round(recall_score(y_test, y_pred), 4),
    "f1":        round(f1_score(y_test, y_pred), 4),
    "roc_auc":   round(roc_auc_score(y_test, y_proba), 4),
}
cm = confusion_matrix(y_test, y_pred)

print(f"\n   FINAL METRICS ({best_name})")
print(f"   {'─'*40}")
for k, v in metrics.items():
    bar = "█" * int(v * 30)
    print(f"   {k:<12}: {v:.4f}  {bar}")
print(f"\n   Confusion Matrix:")
print(f"   TN={cm[0,0]:5}  FP={cm[0,1]:5}")
print(f"   FN={cm[1,0]:5}  TP={cm[1,1]:5}")

#Save Artifacts
print("\n Saving model artifacts")

joblib.dump(final_model, "models/shadowguard_model.pkl")

training_report = {
    "best_model": best_name,
    "final_metrics": metrics,
    "confusion_matrix": cm.tolist(),
    "cv_results": cv_results,
    "feature_columns": feature_cols,
    "tuning_params": param_grids.get(best_name, {}),
}
with open("models/training_report.json", "w") as f:
    json.dump(training_report, f, indent=2)

#Plots
fig, axes = plt.subplots(1, 3, figsize=(18, 5))
fig.suptitle(f"ShadowGuard — {best_name} Performance", fontsize=14, fontweight="bold")

# Confusion matrix
disp = ConfusionMatrixDisplay(cm, display_labels=["Normal", "Attack"])
disp.plot(ax=axes[0], colorbar=False, cmap="Blues")
axes[0].set_title("Confusion Matrix")

# CV model comparison
names = list(cv_results.keys())
f1s = [cv_results[n]["f1"] for n in names]
colors = ["#ef4444" if n == best_name else "#64748b" for n in names]
axes[1].barh(names, f1s, color=colors)
axes[1].set_xlim(0, 1)
axes[1].set_xlabel("F1 Score")
axes[1].set_title("Model Comparison (CV F1)")
for i, v in enumerate(f1s):
    axes[1].text(v + 0.01, i, f"{v:.4f}", va="center", fontsize=9)

# Metrics bar chart
met_keys = list(metrics.keys())
met_vals = list(metrics.values())
bar_colors = ["#22c55e", "#3b82f6", "#f59e0b", "#ef4444", "#8b5cf6"]
bars = axes[2].bar(met_keys, met_vals, color=bar_colors)
axes[2].set_ylim(0, 1.1)
axes[2].set_title("Final Test Metrics")
for bar, val in zip(bars, met_vals):
    axes[2].text(bar.get_x() + bar.get_width()/2, val + 0.01,
                 f"{val:.4f}", ha="center", va="bottom", fontsize=9)

plt.tight_layout()
plt.savefig("models/training_report.png", dpi=150, bbox_inches="tight")


print("Done!")
print(f"  Model:          models/shadowguard_model.pkl")
print(f"  Report JSON:    models/training_report.json")
print(f"  Report Chart:   models/training_report.png")
print(f"  Best Model:     {best_name}")
print(f"  F1 Score:       {metrics['f1']}")
print(f"  AUC-ROC:        {metrics['roc_auc']}")
