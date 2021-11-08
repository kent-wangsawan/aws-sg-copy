# aws-sg-copy

Python script to helps you migrate your AWS VPC Security Groups (SG) from 1 VPC to another VPC in the same or different region.

The script will:

1. Create copy of SGs with the same name and empty rule in the target VPC. SGs created by this script will have tag of `by_sg_migration_script`

2. Copy rules from source SG to the target SG. Rule with SG as its source will have the correct SG referenced.


## Installation

```bash
pip install -r requirements.txt
```

## Usage
1. Make sure to fill the information regarding source and target VPC in the script
```python
import boto3
import botocore.exceptions

### FILL THIS BEFORE EXECUTING
SOURCE_REGION = '' #ap-southeast-1
SOURCE_VPC = '' # vpc-1234abcde
TARGET_REGION = '' #example: ap-southeast-1
TARGET_VPC = '' # vpc-1234abcde
###
```

2. Execute the script
```bash
python3 aws-sg-copy.py
```

## Limitation
1. Both source and target VPC should be within 1 account
2. IP and CIDR Range in the rule will be copied as is.
3. Does not support rule that referencing SG through VPC peering
4. Does not support ec-2 classic Security Group
