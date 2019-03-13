FROM ubuntu
MAINTAINER Fangfan Li <li.fa@husky.neu.edu>
ADD src /wehe
WORKDIR /wehe
RUN chmod +x restartServers.sh
# Files should be saved to /var/spool/wehe/datatype/2016/01/02/file
# e.g. /var/spool/wehe/tcpdump/2016/01/02/file.tcpdump

# To build the docker container:
#   docker build . -t wehe

# To run the docker container:
#   docker run -it wehe
CMD [ "./restartServers.sh" ]
