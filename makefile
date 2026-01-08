all:
	docker compose down
	docker compose stop
	docker compose build
	docker compose up
