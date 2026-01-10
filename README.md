# 🛡️ NeuralShield-ai: AI-Based Phishing Email Detector

## 📌 Overview
NeuralShield-ai is a Machine Learning-powered application designed to detect phishing emails with high accuracy. It analyzes email content, extracts suspicious links, and highlights trigger words used in social engineering attacks.

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

