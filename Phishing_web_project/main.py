import asyncio

from fastapi import FastAPI

from model.model_manager import load_model
from model.model_utility import preprocess_query
from xgboost import XGBClassifier
import sklearn


model = load_model()
app = FastAPI()


@app.get("/")
def read_root():
    return {"Hello": "World"}


@app.get("/predict")
async def predict_survived(url: str):
    query = [[url]]
    print(query)
    url = "https://" + query[0][0]
    print(url)
    query_df = await preprocess_query(url)
    print(query_df)
    prediction = model.predict(query_df)
    print("Prediction result: " + str(prediction))
    return {"IsPhishing": int(prediction)}

# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000, debug=True)
