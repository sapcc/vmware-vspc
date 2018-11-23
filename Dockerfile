##############################

FROM python:3.5
MAINTAINER "Andrew Karpow <andrew.karpow@sap.com>"

WORKDIR /usr/src/app
COPY . .

RUN PBR_VERSION=0.0.3 pip install .

CMD [ "vmware-vspc", "--config-file", "/etc/vspc.conf" ]
