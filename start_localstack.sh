export PORT_WEB_UI=8080
#export SERVICES=lambda,s3,dynamodb,apigateway
docker run -p 4567-4583:4567-4583 -p 8080:8080 localstack/localstack