FROM python:3.10-alpine as base
FROM base as builder

RUN apk add --no-cache git make musl-dev go

# Configure Go
ENV GOROOT /usr/lib/go
ENV GOPATH /go
ENV PATH /go/bin:$PATH

#install osv-scanner
RUN go install github.com/google/osv-scanner/cmd/osv-scanner@v1

RUN apk add build-base
RUN mkdir /install
WORKDIR /install
COPY requirement.txt /requirement.txt
RUN pip install --prefix=/install -r /requirement.txt

FROM base
COPY --from=builder /install /usr/local
COPY --from=builder /go/bin/osv-scanner /usr/local/bin/osv-scanner

RUN mkdir -p /app/agent
ENV PYTHONPATH=/app
COPY agent /app/agent
COPY ostorlab.yaml /app/agent/ostorlab.yaml
WORKDIR /app
CMD ["python3", "/app/agent/osv_agent.py"]
