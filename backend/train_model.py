import os
import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, precision_score, recall_score, f1_score

DATASET = [
    # Phishing / Scam Messages (Label 1)
    ("URGENT: Your account has been suspended. Verify OTP immediately at http://paypa1-security.xyz", 1),
    ("Your Netflix payment failed. Update credit card now: http://netflix-billing.top", 1),
    ("Congratulations! You won $5,000 cash prize. Click http://lottery-claim.club to claim", 1),
    ("Dear customer, suspicious login detected. Enter your OTP to secure account: http://sbi-verify.info", 1),
    ("FINAL NOTICE: Package delivery failed. Pay $2.99 fee now at http://fedex-redelivery.live", 1),
    ("IRS alert: Overdue tax refund of $1420 is pending. Verify SSN at http://irs-tax-refund.cfd", 1),
    ("Your Apple ID has been suspended. Log in at http://appleid-login-fix.com to reactivate", 1),
    ("Amazon: Unauthorized purchase of $899.99 for iPhone. Click http://amz-cancel.top", 1),
    ("Your WhatsApp code is 849-204. Do not share. Verify at http://wa-security.xyz", 1),
    ("Geek Squad: $499 auto-renewal charged. Call or visit http://geeksquad-refund.site", 1),
    ("Security alert: Unauthorized access from Russia. Verify identity: http://google-sec.biz", 1),
    ("PayPal: You received $250. Click http://paypa1-claim.online to deposit to your bank", 1),
    ("Bank alert: Your debit card is blocked. Unblock now: http://hacker-bank.top", 1),
    ("Crypto Alert: 1.5 BTC transferred to unknown wallet. Cancel at http://binance-secure.icu", 1),
    ("URGENT: Password expired for your Microsoft account. Reset at http://micros0ft-pass.com", 1),

    # Legitimate Messages (Label 0)
    ("Hi mom, I will be home by 7 PM for dinner. See you soon!", 0),
    ("Hey team, here is the updated project documentation for next week's sprint review.", 0),
    ("Your flight reservation is confirmed for tomorrow. Safe travels!", 0),
    ("Thanks for your order! Your receipt #49281 has been sent to your email address.", 0),
    ("Hi John, can you review the pull request on GitHub when you get a chance?", 0),
    ("Meeting reminder: Design review session scheduled today at 3:00 PM on Google Meet.", 0),
    ("The library book you requested is now available for pickup at the front desk.", 0),
    ("Happy Birthday Sarah! Hope you have a wonderful day celebrating with family!", 0),
    ("Weather forecast: Expect light rain tomorrow afternoon with high of 68 degrees.", 0),
    ("Here are the notes from today's engineering sync meeting. Let me know if anything is missing.", 0),
    ("Can we reschedule our dentist appointment to Thursday at 10 AM?", 0),
    ("Your electricity bill of $45.20 is due on October 25th.", 0),
    ("Welcome to the team! We are excited to have you join our software engineering group.", 0),
    ("The train schedule has been updated for the holiday weekend.", 0),
    ("Don't forget to submit your weekly status report before 5 PM today.", 0)
]

def train_and_evaluate():
    print("=" * 60)
    print("  ThreatGuard AI — ML Model Training & Evaluation")
    print("=" * 60)

    texts, labels = zip(*DATASET)
    X_train, X_test, y_train, y_test = train_test_split(texts, labels, test_size=0.3, random_state=42, stratify=labels)

    pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(max_features=1000, ngram_range=(1, 2))),
        ('clf', LogisticRegression(C=1.0, random_state=42))
    ])

    pipeline.fit(X_train, y_train)
    y_pred = pipeline.predict(X_test)

    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel() if cm.shape == (2, 2) else (0, 0, 0, 0)
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    print(f"Training Samples: {len(X_train)} | Test Samples: {len(X_test)}")
    print(f"Precision: {prec:.4f}")
    print(f"Recall:    {rec:.4f}")
    print(f"F1 Score:  {f1:.4f}")
    print(f"False Positive Rate (FPR): {fpr:.4f}")
    print("\nConfusion Matrix:")
    print(cm)

    # Save model
    model_path = os.path.join(os.path.dirname(__file__), "ml_model.joblib")
    joblib.dump(pipeline, model_path)
    print(f"\nModel successfully saved to: {model_path}")
    print("=" * 60)

if __name__ == "__main__":
    train_and_evaluate()
