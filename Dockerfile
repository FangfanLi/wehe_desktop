# This image is intended to be run with the appropriate certs mounted in
# /wehe/ssl.
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
# You must provide a local hostname argument when you start this image.
ENTRYPOINT ["/bin/sh", "./startserver.sh"]
