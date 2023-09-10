resource "null_resource" "test" {

  provisioner "local-exec" {
    command = <<-EOT
      echo 'install required packages'
      python3 -m pip install pytest --user
      python3 -m pip install pytest-testinfra --user
      python3 -m pip install paramiko --user
      echo 'start of validation testing'
      python3 -m py.test test_scripts/validation_test.py::function_name -vs
      python3 -m py.test test_scripts/test_efs.py -vs
    EOT
  }
}
