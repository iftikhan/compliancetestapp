#!/bin/bash
set -ex

exec > >(tee /var/log/user-data-application.log|logger -t user-data-application -s 2>/dev/console) 2>&1
set -o xtrace
/etc/eks/bootstrap.sh ${CLUSTER_NAME} --b64-cluster-ca ${B64_CLUSTER_CA} --apiserver-endpoint ${API_SERVER_URL} --kubelet-extra-args --node-labels=eks.amazonaws.com/nodegroup=application


date
echo "all done for eks worker nodes"
