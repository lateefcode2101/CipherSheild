from gensim.models import Word2Vec
import numpy as np

# Example text
text = "how are you"

# Split text into words
words = text.split()

# Train Word2Vec model on the text
model = Word2Vec([words], vector_size=100, window=5, min_count=1, workers=4)


# Function to convert text to numerical vector
def text_to_vector(text, model):
    words = text.split()
    vector = np.zeros(model.vector_size)
    count = 0
    for word in words:
        if word in model.wv:
            vector += model.wv[word]
            count += 1
    if count != 0:
        vector /= count
    return vector


# Function to convert numerical vector to text
def vector_to_text(vector, model):
    words = []
    for component in vector:
        most_similar_word = model.wv.most_similar(positive=[component], topn=1)
        if most_similar_word:
            words.append(most_similar_word[0][0])
    return ' '.join(words)


# Convert text to numerical vector
text_vector = text_to_vector(text, model)
print("Text vector representation:", text_vector)

# Convert numerical vector back to text
reconstructed_text = vector_to_text(text_vector, model)
print("Reconstructed text:", reconstructed_text)
