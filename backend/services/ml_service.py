import os
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from typing import Tuple, Optional, Dict, Any

from ..config import settings

class MLModelService:
    def __init__(self):
        self.pipeline: Optional[Pipeline] = None
        self.is_trained: bool = False
        self._load_or_create_fallback_model()

    def _load_or_create_fallback_model(self):
        if os.path.exists(settings.MODEL_PATH):
            try:
                self.pipeline = joblib.load(settings.MODEL_PATH)
                self.is_trained = True
                print("Loaded ML model from disk successfully.")
                return
            except Exception as e:
                print(f"Failed to load trained model: {e}. Falling back to default model.")

        # Train a default inline baseline model on a curated dataset if file is missing
        self._train_baseline_model()

    def _train_baseline_model(self):
        training_data = [
            # Phishing / Scam samples (1)
            ("URGENT: Your bank account has been locked. Verify your credentials immediately at http://paypa1-security.xyz", 1),
            ("Your Netflix payment failed. Update credit card details now to avoid termination: http://netflix-billing.top", 1),
            ("Congratulations! You won $5,000 cash prize. Click here to claim your reward instantly: http://lottery-claim.club", 1),
            ("Dear customer, suspicious login detected. Enter your OTP 492810 to secure your account or click http://sbi-verify.info", 1),
            ("FINAL NOTICE: Your package could not be delivered. Pay $2.99 fee now at http://fedex-redelivery.live", 1),
            ("IRS alert: Overdue tax refund of $1420 is pending. Verify SSN and bank details at http://irs-tax-refund.cfd", 1),
            ("Your Apple ID has been suspended. Log in at http://appleid-login-fix.com to reactivate", 1),
            ("Amazon: Unauthorized purchase of $899.99 for iPhone 15. If this wasn't you, call 1-800-FAKE or click http://amz-cancel.top", 1),
            ("Your WhatsApp code is 849-204. Do not share this code with anyone. If you didn't request it, click http://wa-security.xyz", 1),
            ("Geek Squad: $499 auto-renewal charged. Call immediately to cancel or visit http://geeksquad-refund.site", 1),
            
            # Legitimate samples (0)
            ("Hi mom, I will be home by 7 PM for dinner. See you soon!", 0),
            ("Hey team, here is the updated project documentation for next week's sprint review.", 0),
            ("Your flight reservation is confirmed for tomorrow. Safe travels!", 0),
            ("Thanks for your order! Your receipt #49281 has been sent to your email address.", 0),
            ("Hi John, can you review the pull request on GitHub when you get a chance?", 0),
            ("Meeting reminder: Design review session scheduled today at 3:00 PM on Google Meet.", 0),
            ("The library book you requested is now available for pickup at the front desk.", 0),
            ("Happy Birthday Sarah! Hope you have a wonderful day celebrating with family!", 0),
            ("Weather forecast: Expect light rain tomorrow afternoon with high of 68 degrees.", 0),
            ("Here are the notes from today's engineering sync meeting. Let me know if anything is missing.", 0)
        ]

        texts, labels = zip(*training_data)
        
        self.pipeline = Pipeline([
            ('tfidf', TfidfVectorizer(max_features=1000, ngram_range=(1, 2))),
            ('clf', LogisticRegression(C=1.0, random_state=42))
        ])
        
        self.pipeline.fit(texts, labels)
        self.is_trained = True
        
        # Save baseline model
        try:
            joblib.dump(self.pipeline, settings.MODEL_PATH)
            print(f"Baseline ML model trained and saved to {settings.MODEL_PATH}")
        except Exception as e:
            print(f"Could not save model to disk: {e}")

    def predict(self, text: str) -> Tuple[float, float, str]:
        if not self.pipeline or not self.is_trained:
            return 0.0, 0.0, "Rule-Based Fallback (Model Unavailable)"

        try:
            # Predict probabilities [prob_legit, prob_phishing]
            probs = self.pipeline.predict_proba([text])[0]
            phishing_prob = float(probs[1])
            confidence = float(max(probs))
            analysis_type = "Trained ML Model (TF-IDF + Logistic Regression)"
            return phishing_prob, confidence, analysis_type
        except Exception as e:
            print(f"Prediction error: {e}")
            return 0.0, 0.0, "Rule-Based Fallback (Prediction Error)"

ml_service = MLModelService()
