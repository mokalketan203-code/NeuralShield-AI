import pandas as pd
import os

# 1. Define sample data (Mocking the Kaggle dataset structure)
data = {
    'text': [
        "Win a $1000 Walmart Gift Card! Click here now!", 
        "Hey, are we still meeting for lunch tomorrow?",
        "URGENT: Your bank account has been compromised. Verify identity.",
        "Project update: The meeting is rescheduled to 3 PM.",
        "Congratulations! You've won a lottery. Claim prize.",
        "Can you send me the files by end of day?",
        "Exclusive offer: 50% off on all medications.",
        "Happy Birthday! Hope you have a great day.",
        "Click this link to reset your password immediately.",
        "Attached is the invoice for your recent purchase."
    ],
    'label_num': [1, 0, 1, 0, 1, 0, 1, 0, 1, 0]  # 1 = Spam (Phishing), 0 = Ham (Safe)
}

# 2. Create the dataframe
df = pd.DataFrame(data)

# 3. Create the 'data' folder if it doesn't exist
if not os.path.exists('data'):
    os.makedirs('data')

# 4. Save to CSV
file_path = 'data/spam_ham_dataset.csv'
df.to_csv(file_path, index=False)

print(f"✅ Success! Created '{file_path}' with sample data.")
print("👉 You can now run 'python train.py'")