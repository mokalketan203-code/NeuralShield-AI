import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import accuracy_score, confusion_matrix, precision_score
import joblib
from preprocess import transform_text  # Importing your function from step 1
from tqdm import tqdm  # <--- MAKE SURE THIS LINE IS HERE!

print("Starting the training process...")

# 1. Load Data
# IMPORTANT: Make sure the file name matches exactly what is in your data folder!
try:
    df = pd.read_csv('data/spam_ham_dataset.csv')
    print("Data Loaded Successfully.")
except FileNotFoundError:
    print("Error: File not found. Check the 'data' folder and filename.")
    exit()

# 2. Preprocessing with a Progress Bar
print("Cleaning text data... (This takes time!)")
tqdm.pandas() # Activate progress bar
# This line shows you the progress bar now:
df['transformed_text'] = df['text'].progress_apply(transform_text)

# 3. Preprocessing (This might take a minute)
print(" Cleaning text data... (this may take a moment)")
# We assume the column with text is named 'text'. If it's 'email', change 'text' to 'email'.
df['transformed_text'] = df['text'].apply(transform_text)

# 4. Vectorization (Converting text to numbers)
print("Converting text to numbers (Vectorizing)...")
tfidf = TfidfVectorizer(max_features=3000)
X = tfidf.fit_transform(df['transformed_text']).toarray()
y = df['label_num'].values # Ensure your target column is named 'label_num' or 'label'

# 5. Splitting Data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=2)

# 6. Model Training (Naive Bayes)
print("Training the AI model...")
mnb = MultinomialNB()
mnb.fit(X_train, y_train)

# 7. Evaluation
y_pred = mnb.predict(X_test)
print("\n---  RESULTS ---")
print("Accuracy Score: ", accuracy_score(y_test, y_pred))
print("Precision Score: ", precision_score(y_test, y_pred))

# 8. Save the Model
print("\n Saving the model to 'models/' folder...")
joblib.dump(tfidf, 'models/vectorizer.pkl')
joblib.dump(mnb, 'models/model.pkl')

print(" DONE! You are ready for the next step.")
