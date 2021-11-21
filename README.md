# Predic-Phishing-Website-project
This is predict phishing website with fast api in local server

## How to install
1. update anaconda in your computer

   ``` conda update -n base conda ```
2. create new visual environment

   ``` conda create -n <your name env> python=3.7 ```
3. install requirement in Directory "/Phishing_web_project/requirement"

   ``` pip install -r requirement.txt ```
4. Start API with server with coman=d line

   ``` uvicorn main:app --reload ```
5. Click IP address and there you go!

  ---
### How to Predict

default ip server: ```127.0.0.1:8000/predict?url=<place your URL who want to predict>```

![alt text](https://miro.medium.com/max/855/1*N--YRIA2NGHJGYQmwxJZcA.png)

 ---
## Warning
- Program will error if 
    1. there are not online website
    2. use only domain name or use only 'www.google.com' as Example
    3. don't input with https:// or http://

Example Input:
  - en.wikipedia.org
  - www.google.com
  - medium.com
