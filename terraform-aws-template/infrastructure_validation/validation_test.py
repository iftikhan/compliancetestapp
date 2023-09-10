import warnings

warnings.filterwarnings('ignore')

import pprint
import pytest
import subprocess
import testinfra
import os
import paramiko
from paramiko import SSHClient
import terraform_variables as tv

# declare custom variables which are not defined
# in terraform variables file
git_version = '2.31.1'
kubectl_version = '1.19'
eksctl_version = '0.99.0'
serverless_version = '3.7.1'
ssh_config_dir = '~/.ssh'
passwordless_ssh_msg = 'passwordless ssh is configured'

# retrieve variables from terraform variables.tf file
# which is stored in <terraform-aws-template/config> dir
terraform_variables = tv.get_terraform_variables()
# pprint.pprint(terraform_variables['tags_default'])
username = terraform_variables['deployment_user']['default']
domain = terraform_variables['tags_default']['default']['Domain']
envname = terraform_variables['envname']['default']
hosted_zone = terraform_variables['hostedzone']['default']
manager_node = 'manager.' + envname + '.' + hosted_zone


def connect_to_manager_node():
    """Returns the paramiko backend for manager node

    Parameters
    ----------
    none

    Returns
    -------
    testinfra.host.Host : testinfra host instance copatible for paramiko backend
    """

    ssh_config_file = os.path.join(ssh_config_dir, 'config')

    return testinfra.get_host('ssh://' + username + '@' + manager_node,
                              ssh_config=os.path.expanduser(ssh_config_file))


@pytest.mark.parametrize(
    ('package_name', 'version'), [("git", git_version), ("unzip", ''),
                                  ("nfs-utils", ''), ("python3-psycopg2", '')])
def test_installed_packages(package_name, version):
    """Tests if specified packages are installed on the manager node

    Parameters
    ----------
    (package_name, version) : tuple
        A tuple containing the package name and version which need to be tested

    Returns
    -------
    none
        Asserts True if the packages are installed and with the correct version
    """
    host = connect_to_manager_node()
    package = host.package(package_name)

    assert package.is_installed, (package_name + " is not installed")
    if version:
        assert package.version.startswith(version), (
            package_name + " is not installed with the correct version")


# test if passwordless ssh is configured
def test_passwordless_ssh_setup(host):
    """Tests if specified packages are installed on the manager node

    Parameters
    ----------
    host: testinfra.host.Host local
        The host in which the script is run

    Returns
    -------
    none
        Asserts True if passwordless ssh is configured on the machine, False otherwise
    """

    cmd = [
        'ssh', '-oNumberOfPasswordPrompts=0', manager_node, 'echo ',
        passwordless_ssh_msg
    ]
    ps = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    output = ps.communicate()[0].decode('utf-8')
    print("output: ", output)

    assert passwordless_ssh_msg in output, "passwordless ssh is not configured for manager node"


# test if ssh into manager node
def test_ssh_to_manager_node_works():
    """Tests if specified packages are installed on the manager node

    Parameters
    ----------
    none

    Returns
    -------
    none
        Asserts True if ssh to manager node is successful without using a password, False otherwise
    """

    client = paramiko.SSHClient()
    client.load_system_host_keys()
    #client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    ssh_private_key_file = os.path.expanduser(
        terraform_variables['ssh_private_key_path']['default'])
    pkey = paramiko.RSAKey.from_private_key_file(ssh_private_key_file)

    client.connect(manager_node, username=username, pkey=pkey, timeout=5000)
    #print("is active: ", client.get_transport().is_active())
    #stdin, stdout, stderr = client.exec_command('ls -la')
    #stdout.channel.recv_exit_status()
    #response = stdout.readlines()
    #print("response: ", response)

    assert client


# test if the correct version of kubectl is installed
def test_kubectl_version():
    """Tests if specified packages are installed on the manager node

    Parameters
    ----------
    none

    Returns
    -------
    none
        Asserts True if kubectl is installed with the correct version, False otherwise
    """

    host = connect_to_manager_node()
    cmd = 'kubectl version'

    output = host.run(cmd).stdout
    print("output: ", output)

    assert kubectl_version in output


# test if eksctl is installed and running
def test_eksctl_installed(host):
    """Tests if specified packages are installed on the manager node

    Parameters
    ----------
    none

    Returns
    -------
    none
        Asserts True if eksctl is installed with the correct version, False otherwise
    """

    host = connect_to_manager_node()
    cmd = 'eksctl version'

    output = host.run(cmd).stdout
    print("output: ", output)

    assert eksctl_version in output


# test if the correct version of serverless is installed
def test_serverless_version(host):
    """Tests if specified packages are installed on the manager node

    Parameters
    ----------
    none

    Returns
    -------
    none
        Asserts True if serverless is installed with the correct version, False otherwise
    """

    host = connect_to_manager_node()
    cmd = 'serverless --version'

    output = host.run(cmd).stdout
    print("output: ", output)

    assert serverless_version in output


# test if aws load balancer controller is installed and running
def test_alb_controller_installed():
    """Tests if specified packages are installed on the manager node

    Parameters
    ----------
    none

    Returns
    -------
    none
        Asserts True if alb-controller is running, False otherwise
    """

    host = connect_to_manager_node()
    cmd = 'kubectl get pods -n kube-system | grep aws-load-balancer-controller'

    output = host.check_output(cmd)
    output = ' '.join(output.split())
    print("output: ", output)

    assert '1/1 Running' in output, "alb-controller is not running"
