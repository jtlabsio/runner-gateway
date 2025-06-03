BLD_DST=./bin/
BLD_FLGS=-v -a -tags netgo
BNRY_NM=gateway
CGO_ENABLED=0
DST=${BLD_DST}${BNRY_NM}
GO_CMD=go

build: download
	${GO_CMD} build ${BLD_FLGS} -o ${DST} ./cmd/...

docker:
	docker build --platform linux/amd64 -t runner-gateway .

download:
	${GO_CMD} mod download

.PHONY: build