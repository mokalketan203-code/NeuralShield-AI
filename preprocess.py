import nltk
from nltk.corpus import stopwords
from nltk.stem.porter import PorterStemmer
import string

# Download necessary NLTK data (only runs once)
nltk.download('punkt')
nltk.download('stopwords')
nltk.download('punkt_tab')

ps = PorterStemmer()

def transform_text(text):
    # 1. Convert to lowercase
    text = text.lower()
    
    # 2. Tokenize (split into words)
    text = nltk.word_tokenize(text)
    
    # 3. Remove special characters and punctuation
    y = []
    for i in text:
        if i.isalnum(): # Keep only alpha-numeric
            y.append(i)
    
    text = y[:]
    y.clear()
    
    # 4. Remove Stopwords (is, am, the, of) and Punctuation
    for i in text:
        if i not in stopwords.words('english') and i not in string.punctuation:
            y.append(i)
            
    text = y[:]
    y.clear()
    
    # 5. Stemming (dancing -> danc, loving -> love)
    for i in text:
        y.append(ps.stem(i))
    
    return " ".join(y)