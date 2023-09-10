output "eks_cluster_iam" {
  value = aws_iam_role.eks_cluster_iam
}

output "endpoint" {
  value = aws_eks_cluster.eks_cluster.endpoint
}

output "eks_cluster" {
    value = aws_eks_cluster.eks_cluster
}

output "kubeconfig-certificate-authority-data" {
  value = aws_eks_cluster.eks_cluster.certificate_authority[0].data
}

output "eks_worker_iam" {
  value = aws_iam_role.zontal_application_nodegroup
}

output "manager_iam" {
  value = aws_iam_role.zontal_application_manager
}

output "add_kube_auth_id" {
  value = null_resource.add_kube_auth.id
}

output "eks_cluster_security_group_id" {
  value = aws_eks_cluster.eks_cluster.vpc_config[0].cluster_security_group_id
}