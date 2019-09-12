FROM python:2.7-alpine
MAINTAINER Fangfan Li <li.fa@husky.neu.edu>, Harsh Modi <modi.ha@husky.neu.edu>
RUN pip install --upgrade pip
RUN apk add --no-cache gcc \
                libc-dev \
		linux-headers \
                mariadb-connector-c-dev \
                python-dev \
		freetype-dev \
		py-numpy \
		py-scipy \
		build-base \
		openblas-dev \
		libgfortran \
		tcpdump \
		wireshark \
		tshark \
		openssl
RUN pip install --no-cache psutil
RUN pip install --no-cache mysqlclient
RUN pip install --no-cache tornado==4.2
RUN pip install --no-cache multiprocessing_logging
RUN pip install --no-cache netaddr
RUN pip install --no-cache future
RUN pip install --no-cache timezonefinder==1.5.3
RUN pip install --no-cache gevent
RUN pip install --no-cache reverse-geocode
RUN pip install --no-cache python-dateutil
RUN pip install --no-cache prometheus_client
RUN apk del --purge gcc \
                libc-dev \
                linux-headers \
		build-base
ADD src /wehe
ADD replayTraces /replayTraces
WORKDIR /wehe
RUN python certGenerator.py --root_cert=/wehe/ssl/ca.crt --root_key=/wehe/ssl/ca.key --destination=/wehe/ssl/ --root_pass=wehepower2HjBqmhqF4
CMD python replay_analyzerServer.py --ConfigFile=configs.cfg --original_ports=True --certs-folders=/wehe/ssl/ & python replay_server.py --ConfigFile=configs.cfg --original_ports=True --certs-folders=/wehe/ssl/