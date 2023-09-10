#!/bin/bash
set -ex

exec > >(tee /var/log/user-data-mongodb.log|logger -t user-data-mongodb -s 2>/dev/console) 2>&1
set -o xtrace
/etc/eks/bootstrap.sh ${CLUSTER_NAME} --b64-cluster-ca ${B64_CLUSTER_CA} --apiserver-endpoint ${API_SERVER_URL} --kubelet-extra-args --node-labels=eks.amazonaws.com/nodegroup=mongodb

date
echo "all done for eks nodes for mongodb"
