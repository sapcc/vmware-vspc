##############################

FROM python:3.5
MAINTAINER "Andrew Karpow <andrew.karpow@sap.com>"
LABEL source_repository="https://github.com/sapcc/vmware-vspc"

WORKDIR /usr/src/app
COPY . .

RUN PBR_VERSION=0.0.3 pip install . dumb-init

CMD [ "vmware-vspc", "--config-file", "/etc/vspc.conf" ]
