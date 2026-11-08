.PHONY: seed api gateway test

seed:
	./scripts/seed.sh

api:
	cd backend && python -m app.main

gateway:
	cd gateway && go run ./cmd/gateway

test:
	cd backend && python -m pytest -q
	cd frontend && npm test
	cd gateway && go test ./...
