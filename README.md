# ansible-collection-analyzer

command example
```
python3 src/analyzer.py -r test-dir/requirements.yml -p test-dir/policy.yaml -o test-dir/result.json
```

```
usage: analyzer.py [-h] [-r REQUIREMENTS_FILE] [-d DOWNLOAD_PATH] [-o OUTPUT_FILE] [-p POLICY]

Ansible Collection Analyzer

optional arguments:
  -h, --help            show this help message and exit
  -r REQUIREMENTS_FILE, --requirements_file REQUIREMENTS_FILE
                        requirements file
  -d DOWNLOAD_PATH, --download_path DOWNLOAD_PATH
                        tmp dir to download the collections to.
  -o OUTPUT_FILE, --output_file OUTPUT_FILE
                        file to export result.
  -p POLICY, --policy POLICY
                        allow policy.
```
