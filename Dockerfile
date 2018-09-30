FROM openwhisk/python3action

RUN apk update && apk add \
    git \
    gmp-dev \
    autoconf \
    flex \
    bison \
    libtool \
    openssl-dev \
    make \
    python-dev

RUN wget http://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz
RUN tar xf pbc-0.5.14.tar.gz
WORKDIR pbc-0.5.14
RUN ./configure
RUN make
RUN make install

RUN git clone https://github.com/JHUISI/charm.git
WORKDIR charm
RUN ./configure.sh
RUN make install
#RUN ldconfig

RUN pip install -r requirements.txt

#WORKDIR /
#RUN mkdir test
#WORKDIR test
#COPY src .
#RUN pwd
#RUN ls
#WORKDIR spike
#RUN pwd
#RUN ls
#WORKDIR ABE
#RUN pwd
#RUN ls
#CMD [ "python", "./main.py" ]
