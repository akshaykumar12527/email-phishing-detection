# email-phishing-detection

1. Use python version 3.7
2. Clone the repository
3. Install libraries using requirements.txt file
> pip install -r requirements.txt
4. Download trained model using "https://s3.amazonaws.com/dl4j-distribution/GoogleNews-vectors-negative300.bin.gz" or copy paste below line in terminal
> wget -c "https://s3.amazonaws.com/dl4j-distribution/GoogleNews-vectors-negative300.bin.gz"
5. Run api.py using terminal
> python api.py
6. The api requests for a json in which the email is stored. You can find one example in example_json_file.js
7. Now open postman, select "POST" request, copy the url from the terminal on which the api is running(by default it is localhost). Now in the tab below select "body", then "raw" and "JSON(application/json)
8. Write email you want to check in the same format as provided in the example_json_file.js
