import pprint
import os
import json
import re
import ast
from pathlib import Path


def get_project_root_dir(cwd, root_indicator):
    """Gets the project root directory

    Parameters
    ----------
    cwd : str
        The current directory from where the script is run
    root_indicator : str
        The name of a file which resides in the root directory. e.g. ".gitlab-ci.yml"
    
    Returns
    -------
    str
        A string representing the absolute path of the project root directory
    """

    root_dir = ''
    flag = 1
    while True and flag:
        for p, d, f in os.walk(cwd):
            if root_indicator in f:
                root_dir = p
                flag = 0

                break
            else:
                cwd = Path(p).parent
                break

    return root_dir


def get_clean_values(line):
    """Extracts variables from a line of text and returns a clean representation of the key/value pairs

    Parameters
    ----------
    line : str
        A line of texts which needs to processed to extract the variables
    
    Returns
    -------
    tuple
        A tuple containing the key and value of a dictionary
    """

    k, v = line.split('=')

    if re.findall(r'"(.*?)"', v):
        v = re.findall(r'"(.*?)"', v)[0]
    elif '#' in v:
        v = v.strip().split('#')[0]

    v = v.strip(' #').replace('\n', '')

    if v.isnumeric():
        v = int(v)
    elif '[' in v or ']' in v:
        v = ast.literal_eval(v)

    return k.strip(' # \"'), v


# extract the variables from all the variables.tf files
def extract_variables(filename):
    """Extracts variables from a terraform(.tf) file

    Parameters
    ----------
    filename : str
        the file name with absolute path containing the variables
    
    Returns
    -------
    dict
        A dictionary containing the clean representation of the variables in the file
    """

    lines = []
    with open(filename, 'r') as f:
        lines = f.readlines()

    dict = {}
    key = ''
    values = {}
    typ = ''
    for idx, line in enumerate(lines):
        if line.strip().startswith('#') or not line.strip():
            continue
        if line.strip().startswith('variable'):
            key = line.split(' ')[1].strip(' \"')
            dict[key] = {}
            continue
        if line.strip().startswith('type'):
            typ = line.split('=')[1].strip()
            dict[key]['type'] = typ
            continue
        else:
            if not any(s in line.strip() for s in ('{', '}')):
                k, v = get_clean_values(line)
                values[k] = v
                continue

            if '}' in line:
                if not 'default' in dict[key]:
                    if 'map' in typ:
                        dict[key]['default'] = values
                    else:
                        dict[key] = values

                    values = {}
                    continue
    #pprint.pprint(dict)

    return dict


def get_terraform_variables():
    """Extracts variables from a terraform(.tf) file

    Parameters
    ----------
    none
    
    Returns
    -------
    dict
        A dictionary containing variables defined in terraform variables file
    """

    # get the gitlab.ci file, which indicates the root path of the project
    gitlab_ci_filename = '.gitlab-ci.yml'
    config_directory = 'config'
    variables_file = 'variables.tf'

    # get the current working directory
    cwd = Path.cwd()

    project_root_dir = get_project_root_dir(cwd, gitlab_ci_filename)

    variables_dict = {}

    for path, subdirs, files in os.walk(project_root_dir):
        if config_directory in path and variables_file in files:
            variables_dict = extract_variables(
                os.path.join(path, variables_file))

    return variables_dict


if __name__ == '__main__':
    get_terraform_variables()
