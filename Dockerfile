FROM python:3.5 as builder
RUN mkdir /install
WORKDIR /install

COPY requirements.txt ./

RUN pip install --install-option="--prefix=/install" -r requirements.txt dumb-init

##############################

FROM python:3.5-alpine
MAINTAINER "Andrew Karpow <andrew.karpow@sap.com>"

WORKDIR /usr/src/app
COPY --from=builder /install /usr/local
COPY . .

RUN PBR_VERSION=0.0.3 python setup.py install

CMD [ "vmware-vspc", "--config-file", "/etc/vspc.conf" ]
