FROM python:3.7.2-stretch

RUN apt-get update
RUN apt-get -y --allow-unauthenticated install \
    python-psycopg2 \
    libpq-dev \
    flex \
    bison \
    libgmp3-dev \
    curl

RUN curl -sL https://deb.nodesource.com/setup_11.x | bash
RUN apt-get install nodejs

COPY ./node-red/flow.json /node-red/flow.json
COPY ./node-red/settings.js /node-red/settings.js
RUN npm install -g --unsafe-perm node-red

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
COPY ./client /client
COPY ./setup.py /setup.py
COPY ./README.md /README.md
COPY ./LICENSE /LICENSE
RUN pip install --editable .

RUN iot-cloud-cli --help
WORKDIR /node-red

EXPOSE 1880
CMD ["node-red", "-s", "./settings.js"]

# To build image: from IoT-Cloud directory - `docker build -t martinheinz/iot_cloud_node_red:0.0.1 -f node-red/Dockerfile .`
# To run container: `docker run -it --network host martinheinz/iot_cloud_node_red`