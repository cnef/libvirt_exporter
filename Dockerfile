# Stage 1: Build libvirt exporter
FROM golang:1.12.17-alpine3.10

# Install dependencies
RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.ustc.edu.cn/g' /etc/apk/repositories
RUN apk add --update git gcc g++ make libc-dev portablexdr-dev linux-headers libnl-dev perl libtirpc-dev pkgconfig wget
RUN wget ftp://xmlsoft.org/libxml2/libxml2-2.9.4.tar.gz -P /tmp && \
    tar -xf /tmp/libxml2-2.9.4.tar.gz -C /tmp
WORKDIR /tmp/libxml2-2.9.4
RUN ./configure --disable-shared --enable-static && \
    make -j2 && \
    make install
RUN wget https://libvirt.org/sources/libvirt-3.2.0.tar.xz -P /tmp && \
    tar -xf /tmp/libvirt-3.2.0.tar.xz -C /tmp
WORKDIR /tmp/libvirt-3.2.0
RUN ./configure --disable-shared --enable-static --localstatedir=/var --without-storage-mpath && \
    make -j2 && \
    make install && \
    sed -i 's/^Libs:.*/& -lnl -ltirpc -lxml2/' /usr/local/lib/pkgconfig/libvirt.pc

# Prepare working directory
ENV LIBVIRT_EXPORTER_PATH=/go/src/github.com/kumina/libvirt_exporter
RUN mkdir -p $LIBVIRT_EXPORTER_PATH
WORKDIR $LIBVIRT_EXPORTER_PATH
COPY . .

# Build and strip exporter
#go get -d ./... && \
RUN go build --ldflags '-extldflags "-static"' && \
    strip libvirt_exporter

# Stage 2: Prepare final image
FROM scratch

# Copy binary from Stage 1
COPY --from=0 /go/src/github.com/kumina/libvirt_exporter/libvirt_exporter .

# Entrypoint for starting exporter
ENTRYPOINT [ "./libvirt_exporter" ]
