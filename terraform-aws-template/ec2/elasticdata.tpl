#!/bin/bash
set -ex

exec > >(tee /var/log/user-data.log|logger -t user-data -s 2>/dev/console) 2>&1

hostnamectl set-hostname ${HOST}.${ENV}.${HOST_ZONE}
dnf install -y policycoreutils nfs-utils zip unzip python3 python3-devel python3-pip gcc createrepo

pip3 install boto3
ln -s /usr/bin/pip3 /usr/bin/pip

# if not ami default user
if ! id ${DEPLOYMENT_USER} > /dev/null 2>&1; then
  adduser ${DEPLOYMENT_USER}
  mkdir -p /home/${DEPLOYMENT_USER}/.ssh
  chmod 700 /home/${DEPLOYMENT_USER}/.ssh
  chown ${DEPLOYMENT_USER}:${DEPLOYMENT_USER} /home/${DEPLOYMENT_USER}/.ssh
  curl -s http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key > /home/${DEPLOYMENT_USER}/.ssh/authorized_keys
  chmod 600 /home/${DEPLOYMENT_USER}/.ssh/authorized_keys
  chown ${DEPLOYMENT_USER}:${DEPLOYMENT_USER} /home/${DEPLOYMENT_USER}/.ssh/authorized_keys
fi

chown -R ${DEPLOYMENT_USER}:${DEPLOYMENT_USER} /home/${DEPLOYMENT_USER}/.ssh
echo '${DEPLOYMENT_USER}         ALL=(ALL)      NOPASSWD: ALL' >> /etc/sudoers

echo "mounting efs volume localy at ${EFS_MOUNT_POINT}"
chown ${DEPLOYMENT_USER}:${DEPLOYMENT_USER} /opt
su - ${DEPLOYMENT_USER} -c "mkdir -p ${EFS_MOUNT_POINT}"
mount -t nfs4 -o nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,noresvport ${EFS_ID}.efs.${REGION}.amazonaws.com:/ ${EFS_MOUNT_POINT}
echo "${EFS_ID}.efs.${REGION}.amazonaws.com:/ ${EFS_MOUNT_POINT} nfs _netdev,noresvport" >>/etc/fstab
date
echo "all done for ES nodes"
