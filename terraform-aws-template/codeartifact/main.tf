module "config" {
  source = "../config"
}

resource "aws_codeartifact_domain" "zontal_domain" {
  domain = join("-", [var.domain_name, "${module.config.envname}"])
}

data "aws_iam_policy_document" "zontal_domain_policy_document" {
  statement {
    sid       = "AllowManagerRoleAccessDomain"
    
    effect    = "Allow"
    principals {
      type        = "AWS"
      identifiers = [
        var.manager_iam.arn
      ]
    }
    actions   = [
      "codeartifact:DescribeDomain",
      "codeartifact:GetAuthorizationToken",
      "codeartifact:GetRepositoryEndpoint",
      "codeartifact:ListTagsForResource",
      "codeartifact:TagResource",
      "codeartifact:UntagResource",
      "sts:GetServiceBearerToken"
    ]
    resources = [
      "*"
    ]
  }
}

resource "aws_codeartifact_domain_permissions_policy" "zontal_domain_policy" {
  domain          = aws_codeartifact_domain.zontal_domain.domain
  policy_document = data.aws_iam_policy_document.zontal_domain_policy_document.json
}

resource "aws_codeartifact_repository" "zontal_repo_pypi" {
  repository  = var.repository_pypi_name
  description = var.repository_pypi_description
  domain      = aws_codeartifact_domain.zontal_domain.domain
}

data "aws_iam_policy_document" "zontal_repo_pypi_policy_document" {
  statement {
    sid       = "AllowManagerRoleAccessPackage"
    
    effect    = "Allow"
    principals {
      type        = "AWS"
      identifiers = [
        var.manager_iam.arn
      ]
    }
    actions   = [
      "codeartifact:DeletePackage",
      "codeartifact:DeletePackageVersions",
      "codeartifact:DescribePackage",
      "codeartifact:DescribePackageVersion",
      "codeartifact:DescribeRepository",
      "codeartifact:DisposePackageVersions",
      "codeartifact:GetAuthorizationToken",
      "codeartifact:GetPackageVersionAsset",
      "codeartifact:GetPackageVersionReadme",
      "codeartifact:GetRepositoryEndpoint",
      "codeartifact:ListPackages",
      "codeartifact:ListPackageVersionAssets",
      "codeartifact:ListPackageVersionDependencies",
      "codeartifact:ListPackageVersions",
      "codeartifact:ListTagsForResource",
      "codeartifact:PublishPackageVersion",
      "codeartifact:PutPackageMetadata",
      "codeartifact:PutPackageOriginConfiguration",
      "codeartifact:ReadFromRepository",
      "codeartifact:TagResource",
      "codeartifact:UntagResource",
      "codeartifact:UpdatePackageVersionsStatus"
    ]
    resources = [
      "*"
    ]
  }
}

resource "aws_codeartifact_repository_permissions_policy" "zontal_repo_pypi_policy" {
  repository      = aws_codeartifact_repository.zontal_repo_pypi.repository
  domain          = aws_codeartifact_domain.zontal_domain.domain
  policy_document = data.aws_iam_policy_document.zontal_repo_pypi_policy_document.json
}
