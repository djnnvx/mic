TARGET 		= mic
SRC 		= main.go

.PHONY: all
all: compile

.PHONY: help
help:
	@echo "\033[34mtargets:\033[0m"
	@perl -nle'print $& if m{^[a-zA-Z_-\d]+:.*?## .*$$}' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-22s\033[0m %s\n", $$1, $$2}'

.PHONY: compile
compile: ## compile the project
	@go build -o $(TARGET) $(SRC)

.PHONY: docker
docker: ## builds a docker image from source
	@docker build -t $(TARGET) .

.PHONY: clean
clean: ## cleans up the project
	rm -f $(TARGET)

.PHONY: tidy
tidy: ## runs tidy and formatting
	@go mod tidy
	@gofmt -s -w .
