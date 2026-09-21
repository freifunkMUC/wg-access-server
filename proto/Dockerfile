FROM node:26.8.2-bookworm AS proto-js
RUN apt-get update && apt-get install -y protobuf-compiler libprotobuf-dev
WORKDIR /code
COPY ./website/package.json ./
COPY ./website/package-lock.json ./
RUN npm ci --no-audit --prefer-offline
# Mount ./proto to /proto
# Mount ./website/src/sdk to /code/src/sdk
CMD ["npm", "run", "codegen"]

FROM golang:1.27.1-alpine AS proto-go
RUN apk add --no-cache protobuf protobuf-dev
WORKDIR /code

COPY ./go.mod ./go.sum ./
RUN go install tool
# Mount ./proto to /code/proto
COPY ./codegen.sh ./
CMD ["./codegen.sh"]
