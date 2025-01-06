run:    open-api
	go run main.go
pg:
	cd postgresql && docker-compose down && docker-compose up -d
open-api:
	swag init
