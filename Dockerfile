FROM golang:1.24-alpine AS build 
RUN apk update && apk upgrade && apk add --no-cache git make ca-certificates
ENV blddir=/tmp/bld 
ENV dstdir=/tmp/dst 

# compile the tool
WORKDIR ${blddir} 
COPY . ${blddir}
ENV CGO_ENABLED=0
RUN make build && \
  mkdir -p ${dstdir} && \
  cp -r bin/gateway settings ${dstdir}

# create runtime
FROM alpine:latest AS runtime 
ENV blddst=/tmp/dst 
ENV bindst=/opt/gateway 

RUN rm -rf /bin/*
WORKDIR ${bindst}
COPY --from=build ${blddst} ${bindst}
EXPOSE 8443
ENTRYPOINT ["/opt/gateway/gateway"]