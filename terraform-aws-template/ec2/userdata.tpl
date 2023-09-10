#!/bin/bash
set -ex

exec > >(tee /var/log/user-data.log|logger -t user-data -s 2>/dev/console) 2>&1

hostnamectl set-hostname ${HOST}.${ENV}.${HOST_ZONE}

dnf -y install  epel-release
dnf config-manager -y --add-repo=https://download.docker.com/linux/centos/docker-ce.repo
dnf -y install wget git nfs-utils vim python3 python3.9 cifs-utils createrepo libselinux-python3 screen python3-psycopg2 zip unzip
dnf -y install docker-ce postgresql java-11

pip3 install boto3 docker psycopg2 twine
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

su - ${DEPLOYMENT_USER} -c "curl 'https://awscli.amazonaws.com/awscli-exe-linux-x86_64-2.9.15.zip' -o 'awscliv2.zip'"
su - ${DEPLOYMENT_USER} -c "unzip awscliv2.zip"
sh /home/${DEPLOYMENT_USER}/aws/install

echo "mounting efs volume"
chown ${DEPLOYMENT_USER}:${DEPLOYMENT_USER} /opt
su - ${DEPLOYMENT_USER} -c "mkdir -p ${EFS_MOUNT_POINT}"
mount -t nfs4 -o nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,noresvport ${EFS_ID}.efs.${REGION}.amazonaws.com:/ ${EFS_MOUNT_POINT}
chmod -R 777 ${EFS_MOUNT_POINT}

echo "${EFS_ID}.efs.${REGION}.amazonaws.com:/ ${EFS_MOUNT_POINT} nfs _netdev,noresvport" >>/etc/fstab

echo "mounting mongo efs volume"
su - ${DEPLOYMENT_USER} -c "mkdir -p ${EFS_MONGO_MOUNT_POINT}"
mount -t nfs4 -o nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,noresvport ${EFS_MONGO_ID}.efs.${REGION}.amazonaws.com:/ ${EFS_MONGO_MOUNT_POINT}
chmod -R 777 ${EFS_MONGO_MOUNT_POINT}

echo "${EFS_MONGO_ID}.efs.${REGION}.amazonaws.com:/ ${EFS_MONGO_MOUNT_POINT} nfs _netdev,noresvport" >>/etc/fstab

echo "running OS configuration items"
su - ${DEPLOYMENT_USER} -c "mkdir -p /opt/cmd_deployment_master/customer_certs"
setsebool -P httpd_can_network_connect 1
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables-save
echo "iptables done"

echo "setup ssh config file"

su - ${DEPLOYMENT_USER} -c "cat <<EOF | tee -a /home/${DEPLOYMENT_USER}/.ssh/config
Host `hostname`
  HostName `hostname`
  User ${DEPLOYMENT_USER}
  IdentityFile ${KEY}
EOF"
su - ${DEPLOYMENT_USER} -c "ssh-keyscan `hostname` >>~/.ssh/known_hosts"
%{ for s in ES_HOSTS ~}
su - ${DEPLOYMENT_USER} -c "cat <<EOF | tee -a /home/${DEPLOYMENT_USER}/.ssh/config
Host ${s}.${ENV}.${HOST_ZONE}
  HostName ${s}.${ENV}.${HOST_ZONE}
  User ${DEPLOYMENT_USER}
  IdentityFile ${KEY}
EOF"
su - ${DEPLOYMENT_USER} -c "ssh-keyscan ${s}.${ENV}.${HOST_ZONE}>>~/.ssh/known_hosts"
%{ endfor ~}

chmod 600 /home/${DEPLOYMENT_USER}/.ssh/config
chown ${DEPLOYMENT_USER}:${DEPLOYMENT_USER} /home/${DEPLOYMENT_USER}/.ssh/config

echo "configuring kubeconfig"
dnf -y install bash-completion
su - ${DEPLOYMENT_USER} -c "aws eks --region ${REGION} update-kubeconfig --name ${EKS_CLUSTER_NAME}"

su - ${DEPLOYMENT_USER} -c "echo 'alias k=kubectl'>>~/.bashrc"

su - ${DEPLOYMENT_USER} -c "echo 'source /usr/share/bash-completion/bash_completion' >>~/.bashrc"

su - ${DEPLOYMENT_USER} -c "echo 'source <(kubectl completion bash)' >>~/.bashrc"

su - ${DEPLOYMENT_USER} -c "source ~/.bashrc"

#echo "userdata done for management node"


su - ${DEPLOYMENT_USER} -c "curl -o- -L https://tf-installation-packages.s3.eu-central-1.amazonaws.com/1.0/installable-packages/serverless.sh | VERSION=3.7.1 bash"

su - ${DEPLOYMENT_USER} -c "sudo cp /home/${DEPLOYMENT_USER}/.serverless/bin/* /usr/bin"
serverless -v

#Install ansible
dnf -y install /tmp/ansible-2.9.27-3.el8.noarch.rpm

curl --silent --location "https://github.com/weaveworks/eksctl/releases/latest/download/eksctl_$(uname -s)_amd64.tar.gz" | tar xz -C /tmp
mv /tmp/eksctl  /usr/local/bin
eksctl version
eksctl get cluster --name=${EKS_CLUSTER_NAME} --region=${REGION}

#Install ALB

#downloadhelm
#su - ${DEPLOYMENT_USER} -c "mkdir bin"
echo "downloading HELM"
helmTar="helm-v3.7.0-linux-amd64.tar.gz"
su - ${DEPLOYMENT_USER} -c "curl -LO https://get.helm.sh/$helmTar"
su - ${DEPLOYMENT_USER} -c "tar --strip-components=1 -xzf $helmTar -C bin linux-amd64/helm"
su - ${DEPLOYMENT_USER} -c "chmod 755 \$HOME/bin/helm"
su - ${DEPLOYMENT_USER} -c "rm $helmTar"
cp /home/${DEPLOYMENT_USER}/bin/helm    /usr/bin

echo "download finish"

# prepare install alb-controller
echo "module.eks.null_resource.add_kube_auth.id=${ADD_KUBE_AUTH_ID} - kube authmap has been ready for installing alb-controller"
su - ${DEPLOYMENT_USER} -c "helm repo add eks https://aws.github.io/eks-charts"
su - ${DEPLOYMENT_USER} -c "helm repo update"
#su - ${DEPLOYMENT_USER} -c "mkdir alb-controller"
#su - ${DEPLOYMENT_USER} -c "cd alb-controller"
#su - ${DEPLOYMENT_USER} -c "wget https://codeload.github.com/kubernetes-sigs/aws-load-balancer-controller/zip/refs/heads/main"
#su - ${DEPLOYMENT_USER} -c "unzip main"
#su - ${DEPLOYMENT_USER} -c "kubectl apply -f /home/${DEPLOYMENT_USER}/aws-load-balancer-controller-main/helm/aws-load-balancer-controller/crds/crds.yaml"

# helm install alb-controller
su - ${DEPLOYMENT_USER} -c "helm install aws-load-balancer-controller eks/aws-load-balancer-controller --version ${ALB_CHART_VERSION} --set clusterName=${EKS_CLUSTER_NAME} --set serviceAccount.create=true --set region=${REGION} --set vpcId=${VPC_ID} --set serviceAccount.name=aws-load-balancer-controller -n kube-system --set image.repository=${ALB_REGISTRY_IMAGE} --set enableWaf=false --set enableWafv2=false --set enableShield=false --set image.tag=${ALB_CONTROLLER_IMAGE_TAG}"
echo "install done"
#change serviceaccount eks.amazonaws.com/role-arn: arn:aws:iam::521310437492:role/zontal-application-nodegroup
su - ${DEPLOYMENT_USER} -c "kubectl annotate --overwrite serviceaccount aws-load-balancer-controller -n kube-system eks.amazonaws.com/role-arn=${ALB_IAM_ARN}"

#restart the ALB pods
su - ${DEPLOYMENT_USER} -c "kubectl scale -n kube-system --replicas=0 deployment/aws-load-balancer-controller"
su - ${DEPLOYMENT_USER} -c "kubectl scale -n kube-system --replicas=1 deployment/aws-load-balancer-controller"


# Export variables for Ansible
su - ${DEPLOYMENT_USER} -c "cd /home/${DEPLOYMENT_USER}"
su - ${DEPLOYMENT_USER} -c "mkdir terraform_variables"
su - ${DEPLOYMENT_USER} -c "echo 'aws_platform_secret_arn: ${SM_ID}'  >> /home/${DEPLOYMENT_USER}/terraform_variables/tf_ansible_vars_file.yml"
su - ${DEPLOYMENT_USER} -c "echo 'aws_platform_security_group_id: ${LAMBDA_SG_ID}  #<envname>-platform-lambdaSg'  >> /home/${DEPLOYMENT_USER}/terraform_variables/tf_ansible_vars_file.yml"
su - ${DEPLOYMENT_USER} -c "echo 'aws_platform_subnet_ids: ${SERVERLESS_NODE_GROUP_SUBNET_IDS} #serverless_node_group_subnets'  >> /home/${DEPLOYMENT_USER}/terraform_variables/tf_ansible_vars_file.yml"
su - ${DEPLOYMENT_USER} -c "echo 'aws_eks_node_group_subnet_ids: ${EKS_NODE_GROUP_SUBNET_IDS}'  >> /home/${DEPLOYMENT_USER}/terraform_variables/tf_ansible_vars_file.yml"
su - ${DEPLOYMENT_USER} -c "echo 'aws_platform_sns_notification_topic_arn: ${SNS_NOTIFICATION_TOPIC_ARN}'  >> /home/${DEPLOYMENT_USER}/terraform_variables/tf_ansible_vars_file.yml"
su - ${DEPLOYMENT_USER} -c "echo 'aws_platform_sns_notification_fifo_topic_arn: ${SNS_NOTIFICATION_FIFO_TOPIC_ARN}'  >> /home/${DEPLOYMENT_USER}/terraform_variables/tf_ansible_vars_file.yml"
su - ${DEPLOYMENT_USER} -c "echo 'aws_platform_sqs_notification_fifo_queue_url: ${SQS_NOTIFICATION_FIFO_QUEUE_URL}'  >> /home/${DEPLOYMENT_USER}/terraform_variables/tf_ansible_vars_file.yml"
su - ${DEPLOYMENT_USER} -c "echo 'access_secret: ${ACCESS_SECRET} #base64 encoded'  >> /home/${DEPLOYMENT_USER}/terraform_variables/tf_ansible_vars_file.yml"
su - ${DEPLOYMENT_USER} -c "echo 'dns_name: ${ENV}.${HOST_ZONE}'  >> /home/${DEPLOYMENT_USER}/terraform_variables/tf_ansible_vars_file.yml"
su - ${DEPLOYMENT_USER} -c "echo 'aws_eks_cluster_security_group_id: ${EKS_CLUSTER_SECURITY_GROUP_ID}'  >> /home/${DEPLOYMENT_USER}/terraform_variables/tf_ansible_vars_file.yml"
su - ${DEPLOYMENT_USER} -c "echo 'aws_zontal_application_security_group_id: ${ZONTAL_APPLICATION_SG_ID}'  >> /home/${DEPLOYMENT_USER}/terraform_variables/tf_ansible_vars_file.yml"
su - ${DEPLOYMENT_USER} -c "echo 'aws_efs_volume_id: ${EFS_ID}'  >> /home/${DEPLOYMENT_USER}/terraform_variables/tf_ansible_vars_file.yml"
su - ${DEPLOYMENT_USER} -c "echo 'aws_efs_mongo_volume_id: ${EFS_MONGO_ID}'  >> /home/${DEPLOYMENT_USER}/terraform_variables/tf_ansible_vars_file.yml"
su - ${DEPLOYMENT_USER} -c "echo 'aws_rds_host: ${RDS_HOSTNAME}'  >> /home/${DEPLOYMENT_USER}/terraform_variables/tf_ansible_vars_file.yml"
su - ${DEPLOYMENT_USER} -c "echo 'aws_rds_port: ${RDS_PORT}'  >> /home/${DEPLOYMENT_USER}/terraform_variables/tf_ansible_vars_file.yml"
su - ${DEPLOYMENT_USER} -c "echo 'aws_rds_db_name: ${RDS_DB_NAME}'  >> /home/${DEPLOYMENT_USER}/terraform_variables/tf_ansible_vars_file.yml"
su - ${DEPLOYMENT_USER} -c "echo 'aws_rds_password: ${RDS_PASSWORD}'  >> /home/${DEPLOYMENT_USER}/terraform_variables/tf_ansible_vars_file.yml"

echo "set environment variables"
su - ${DEPLOYMENT_USER} -c "echo 'export SQS_TRANSITIONS_RETRY_URL=${SQS_TRANSITIONS_RETRY_URL}'>>~/.bashrc"
su - ${DEPLOYMENT_USER} -c "echo 'export SQS_TRANSITIONS_RETRY_ARN=${SQS_TRANSITIONS_RETRY_ARN}'>>~/.bashrc"
su - ${DEPLOYMENT_USER} -c "echo 'export SNS_TRANSITIONS_FAILURE_TOPIC_ARN=${SNS_TRANSITIONS_FAILURE_TOPIC_ARN}'>>~/.bashrc"
su - ${DEPLOYMENT_USER} -c "source ~/.bashrc"

echo "userdata done for management node"
