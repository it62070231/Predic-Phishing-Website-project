import pandas as pd

from model.model_utility import load_deployable_model, preprocess_query
import json
import pandas
import os


def load_model():
    op_dir = '/trained_model/'
    model_file = 'trained_xgboost_model.plk'

    model = load_deployable_model(os.getcwd() + op_dir + model_file)
    return model


def main():
    path_parent = os.path.dirname(os.getcwd())
    os.chdir(path_parent)

    model = load_model()
    print(model)
    json_item = {
        "url": "https://www.google.com"
    }

    json_string = json.dumps(json_item)

    query_dict = json.loads(json_string)

    query_df = pd.json_normalize(query_dict)

    new_query_df = preprocess_query(query_df)

    prediction = model.predict(new_query_df)

    print("Prediction result: " + str(prediction))


# this means that if this script is executed, then
# main() will be executed
if __name__ == '__main__':
    main()
