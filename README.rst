IoT Cloud
========================

Privacy friendly framework for IoT Cloud.


---------------

Running Localstack

- ./start.sh from /c/Program Files/Docker Tools + docker run localstack/localstack (causes error Forwarding request on Windows)
- python localstack start (from C:\Program Files\Python36\Scripts, but causes error with ElasticSearch)
- set SERVICES=lambda,s3,dynamodb,... + python localstack start (from C:\Program Files\Python36\Scripts, causes error with permission denied)


