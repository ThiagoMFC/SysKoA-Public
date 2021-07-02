FROM golang:1.14

ENV GOPATH=/go/

WORKDIR /go/

COPY . .

RUN ls

WORKDIR /src/

RUN ls

RUN go get -u golang.org/x/crypto/bcrypt
RUN go get -u github.com/dustin/go-humanize
RUN go get -u github.com/julienschmidt/httprouter
RUN go get -u github.com/rs/cors
RUN go get -u github.com/dgrijalva/jwt-go
RUN go get github.com/grokify/html-strip-tags-go
RUN go get gopkg.in/mgo.v2

RUN ls

WORKDIR /go/

RUN ls

RUN go build

EXPOSE 8080

CMD ["./go"]



