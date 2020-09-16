NAME=justencrypt
VERSION=0.0.1
TAG=${NAME}:${VERSION}
CSS_PATH=$$(pwd)

conn: connect

connect: 
	@docker exec -it ${NAME} /bin/sh

build:
	@docker build --tag ${TAG} .

down:
	@docker stop ${NAME}

up: build
	@docker run -d --rm \
	    -it \
	    -p 8080:80 \
	    --name ${NAME} \
		-v ${CSS_PATH}:/usr/share/nginx/html \
		${TAG}

stop: down
