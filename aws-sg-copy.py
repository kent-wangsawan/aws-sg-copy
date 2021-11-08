import boto3
import botocore.exceptions

## FILL THIS BEFORE EXECUTING
SOURCE_REGION = '' #ap-southeast-1
SOURCE_VPC = '' # vpc-1234abcde
TARGET_REGION = '' #example: ap-southeast-1
TARGET_VPC = '' # vpc-1234abcde
##

ec2_s_client = boto3.client('ec2', region_name=SOURCE_REGION)
ec2_resource = boto3.resource('ec2', region_name=SOURCE_REGION)

ec2_t_client = boto3.client('ec2', region_name=TARGET_REGION)

def main():
	is_pass = validate_param()
	if not is_pass: return

	# Get all SG id in the VPC
	sg_source_ids = get_source_sg(SOURCE_VPC)
	print('#-#-#-#', len(sg_source_ids), ' Security Groups from VPC ', SOURCE_VPC, ' found.' )

	# Create new SGs into the target VPC
	# Map source SG id with target SG id
	# New SG don't have rule corresponded yet
	print('-----------------------')
	print('#-#-#-# Creating Security Group in target VPC ', TARGET_VPC)
	map_sg_source_target = {}
	for source_sg_id in sg_source_ids:
		target_sg = create_sg_target(source_sg_id)
		map_sg_source_target[source_sg_id] = target_sg['GroupId']

	# Copy the SG Rule
	print('-----------------------')
	print('#-#-#-# Creating Security Group Rule in target VPC ', TARGET_VPC)
	for source_sg_id in sg_source_ids:
		copy_sg_inbound_rule(SOURCE_VPC, source_sg_id, map_sg_source_target)
		copy_sg_outbound_rule(SOURCE_VPC, source_sg_id, map_sg_source_target)

def get_source_sg(source_vpc_id):
	sg_source_ids = []
	nextToken = ''
	
	while nextToken != None:
		resp = ec2_s_client.describe_security_groups(
			Filters = [{'Name':'vpc-id', 'Values':[source_vpc_id]}],
			NextToken = nextToken,
			MaxResults = 50)
		nextToken = resp.get('NextToken', None)

		for sg in resp.get('SecurityGroups', []):
			sg_source_ids.append(sg['GroupId'])

	return sg_source_ids

def create_sg_target(source_sg_id):	
	resp = ec2_s_client.describe_security_groups(
		Filters = [
			{'Name':'vpc-id', 'Values':[SOURCE_VPC]},
			{'Name':'group-id', 'Values':[source_sg_id]}
		]
	)
	sourceSG = resp['SecurityGroups'][0]
	print('Creating Security Group in target for: ', sourceSG['GroupName'])

	new_sg = None
	try:
		new_sg = ec2_t_client.create_security_group(
			VpcId = TARGET_VPC,
			GroupName = sourceSG['GroupName'],
			Description = sourceSG['Description'],
			TagSpecifications=[{
				'ResourceType':'security-group',
				'Tags': [{'Key':'by_sg_migration_script', 'Value':'1'}]
			}]
		)
	except botocore.exceptions.ClientError as error:
		if error.response['Error']['Code'] in ('InvalidGroup.Duplicate', 'InvalidParameterValue'):
			resp = ec2_t_client.describe_security_groups(
				Filters = [
					{'Name':'vpc-id', 'Values':[TARGET_VPC]},
					{'Name':'group-name', 'Values': [sourceSG['GroupName']]}
				]
			)
			new_sg = resp['SecurityGroups'][0]
			print("\t--> SG {0} is already exist with id {1}".format(sourceSG['GroupName'], new_sg['GroupId']))
	return new_sg

def copy_sg_inbound_rule(source_vpc_id, source_sg_id, map_sg_source_target):
	target_sg_id = map_sg_source_target[source_sg_id]
	source_sg = ec2_resource.SecurityGroup(source_sg_id)

	print('Copying inbound rules for security group ', source_sg.group_name)
	
	for rule in source_sg.ip_permissions:
		if rule.get('IpRanges', False):
			duplicate_rule = dict(rule)
			duplicate_rule.pop('UserIdGroupPairs')
			try:
				resp = ec2_t_client.authorize_security_group_ingress(
					GroupId = target_sg_id,
					IpPermissions = [duplicate_rule]
				)
			except botocore.exceptions.ClientError as error:
				if error.response['Error']['Code'] in ('InvalidPermission.Duplicate'):
					print('\t--> Rule already exist, skipping')
				else:
					raise
		if rule.get('UserIdGroupPairs', False): 
			duplicate_rule = dict(rule)
			duplicate_rule.pop('IpRanges')
			for v in duplicate_rule['UserIdGroupPairs']:
				v['GroupId'] = map_sg_source_target[v['GroupId']]
			try:
				resp =  ec2_t_client.authorize_security_group_ingress(
					GroupId = target_sg_id,
					IpPermissions = [duplicate_rule]
				)
			except botocore.exceptions.ClientError as error:
				if error.response['Error']['Code'] in ('InvalidPermission.Duplicate'):
					print('\t--> Rule already exist, skipping')
				else:
					raise

def copy_sg_outbound_rule(source_vpc_id, source_sg_id, map_sg_source_target):
	target_sg_id = map_sg_source_target[source_sg_id]
	source_sg = ec2_resource.SecurityGroup(source_sg_id)

	print('Copying outbound rules for security group ', source_sg.group_name)
	
	for rule in source_sg.ip_permissions_egress:
		if rule.get('IpRanges', False):
			duplicate_rule = dict(rule)
			duplicate_rule.pop('UserIdGroupPairs')
			try:
				resp = ec2_t_client.authorize_security_group_egress(
					GroupId = target_sg_id,
					IpPermissions = [duplicate_rule]
				)
			except botocore.exceptions.ClientError as error:
				if error.response['Error']['Code'] in ('InvalidPermission.Duplicate'):
					print('\t--> Rule already exist, skipping')
				else:
					raise
		if rule.get('UserIdGroupPairs', False): 
			duplicate_rule = dict(rule)
			duplicate_rule.pop('IpRanges')
			for v in duplicate_rule['UserIdGroupPairs']:
				v['GroupId'] = map_sg_source_target[v['GroupId']]
			try:
				resp =  ec2_t_client.authorize_security_group_egress(
					GroupId = target_sg_id,
					IpPermissions = [duplicate_rule]
				)
			except botocore.exceptions.ClientError as error:
				if error.response['Error']['Code'] in ('InvalidPermission.Duplicate'):
					print('\t--> Rule already exist, skipping')
				else:
					raise

def validate_param():
	required_params = [SOURCE_REGION, SOURCE_VPC, TARGET_REGION, TARGET_VPC]

	if '' in required_params:
		print("!!! SOURCE_REGION, SOURCE_VPC, TARGET_REGION, TARGET_VPC cannot be empty")
		return False

	return True


main()