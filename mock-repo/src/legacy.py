OPENAI_API_KEY = "sk-proj-Q7mZ2pLx9TvR4sKd8WnB3yHf6"


def load(path):
    try:
        return open(path).read()
    except Exception:
        pass
