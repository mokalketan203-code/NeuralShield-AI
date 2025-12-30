# 🛡️ SafeGuard: AI-Based Phishing Email Detector

## 📌 Overview
SafeGuard is a Machine Learning-powered application designed to detect phishing emails with high accuracy. It analyzes email content, extracts suspicious links, and highlights trigger words used in social engineering attacks.

## 🚀 Features
* **AI Detection:** Uses a Naive Bayes Classifier (94.6% Accuracy) to classify emails as "Safe" or "Phishing".
* **Threat Intelligence:** Automatically extracts URL links and detects keyword patterns (e.g., "Urgent", "Bank").
* **Confidence Score:** Displays the probability of the prediction (e.g., "98.5% Sure").
* **Feedback Loop:** Users can report incorrect results to help retrain the model.

## 🛠️ Tech Stack
* **Python:** Core Logic
* **Scikit-Learn:** Machine Learning (MultinomialNB)
* **Streamlit:** User Interface
* **NLTK:** Natural Language Processing (Text Cleaning)

## 📂 Project Structure
* `train.py`: The "Brain" - Trains the model and saves it.
* `app.py`: The "Face" - The web application interface.
* `preprocess.py`: Helper script for cleaning text.
* `models/`: Stores the trained `.pkl` files.

## 💿 How to Run
1.  Install dependencies: `pip install -r requirements.txt`
2.  Run the app: `python -m streamlit run app.py`

---
*Built as a 4-Day AI Sprint Project.*





######
**
` i want add this things on my project Things you did well ✅

Session state usage (many beginners miss this)
Modular helper functions

Defensive error handling for missing models
Small improvement ideas
Highlight keywords inside the email text
Add URL reputation check (e.g., domain length, IP-based URLs)
Handle class imbalance if phishing data is skewed
also this [Security improvements
Model improvement ideas]
* #

# give me 15 some Small improvement ideas for this project 
##