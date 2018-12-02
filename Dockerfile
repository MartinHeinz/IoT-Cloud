FROM python:3.7-stretch

RUN apt-get update
RUN apt-get -y install \
    python-psycopg2 \
    libpq-dev \
    flex \
    bison \
    libgmp3-dev

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
RUN ldconfig

COPY ./requirements.txt requirements.txt
RUN pip install -r requirements.txt

WORKDIR /
COPY ./app /app