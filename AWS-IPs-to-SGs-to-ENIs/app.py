import boto3
import hashlib
import json
import logging
import urllib.request, urllib.error, urllib.parse
import os
import string
import time
import math

INGRESS_PORTS = os.getenv('PORTS', '80').split(',')     # csv list of ports and port-ranges
SERVICE = os.getenv('SERVICE', 'CLOUDFRONT')
NAME = os.getenv('PREFIX_NAME', 'AUTOUPDATE')
REGIONS = os.getenv('REGIONS','eu-west-1').split(',')   # Region where SGs should be created

# Set up logging
if len(logging.getLogger().handlers) > 0:
    logging.getLogger().setLevel(logging.ERROR)
else:
    logging.basicConfig(level=logging.DEBUG)

# Enable verbose logs according to env
if os.getenv('DEBUG') == 'true':
    logging.getLogger().setLevel(logging.INFO)

def lambda_handler(event, context):    
    # Retrieve updated IP ranges from url contained in received SNS message
    message = json.loads(event['Records'][0]['Sns']['Message'])
    url = message['url']
    logging.info('Requesting IP changes from ' + url)
    ip_json = urllib.request.urlopen(url).read()

    # Verify expected and calculated hashes match
    expected_hash = message['md5']
    calculated_hash = hashlib.md5(ip_json).hexdigest()
    if calculated_hash != expected_hash:
        raise Exception(f'MD5 Mismatch: got {calculated_hash} expected {expected_hash}')

    # Import IP ranges from json payload, then SERVICE's subset of IPs within that
    ip_ranges = json.loads (ip_json)
    svc_ranges = [prefix['ip_prefix'] for prefix in ip_ranges['prefixes'] if prefix['service'] == SERVICE]

    # Derive total number of rules required (i.e. ranges * ports)
    ranges = len(svc_ranges)
    ports = len(INGRESS_PORTS)
    total_rules = ranges * ports

    # Construct array of rules for each port/port-range and each CIDR range
    rules = []
    for port_range in INGRESS_PORTS:
        for cidr in svc_ranges:
            rules.append({
                'FromPort': int(port_range.split('-',1)[0]),
                'ToPort': int(port_range.split('-',1)[-1]),
                'IpRanges': [{ 'CidrIp': cidr, 'Description': f'{SERVICE} rule {len(rules)+1} of {total_rules}'}],
                'IpProtocol': 'tcp'
                })

    # SG label = IP range publish time + elpased seconds since then
    elapsed = int(time.time()) - int(ip_ranges['syncToken'])
    sg_label = f"{ip_ranges['createDate']}+{elapsed}"

    # Process SG renewals for each region specified
    for region in REGIONS:

        logging.info(f'Processing SG renewals for region {region}')

        # Get region-specific Service-Quotas (rules-per-SG and SGs-per-ENI)
        sq_client = boto3.client('service-quotas', region_name=region)
        max_rules_per_sg = int(sq_client.get_service_quota(ServiceCode='vpc', QuotaCode='L-0EA8095F')['Quota']['Value']) # Inbound or outbound rules per security group
        max_sgs_per_eni  = int(sq_client.get_service_quota(ServiceCode='vpc', QuotaCode='L-2AFB9258')['Quota']['Value']) # Security groups per network interface
        
        # Derive number of SGs required to hold all rules in this region
        total_sgs_rqd = math.ceil(total_rules / max_rules_per_sg)
        logging.info(f'{total_sgs_rqd} new SGs are needed to host {total_rules} rules at max {max_rules_per_sg} rules per SG, i.e. {ranges} cidr ranges x {ports} port ranges {*INGRESS_PORTS,}')

        # Create ec2 boto3 client 
        ec2_client = boto3.client('ec2', region_name=region)
        
        # Limitation: Assumes default VPC's id 
        vpc_id = ec2_client.describe_vpcs(Filters=[{'Name':'isDefault','Values': ['true']},])['Vpcs'][0]['VpcId']

        # Set filter to search for tagged SGs and ENIs
        filters = [ { 'Name': 'tag-key',   'Values': ['PREFIX_NAME'] },
                    { 'Name': 'tag-value', 'Values': [NAME] },
                    { 'Name': 'vpc-id',    'Values': [vpc_id] } ]

        # Get list of old SGs to delete, based on tag filter
        sgs = ec2_client.describe_security_groups(Filters=filters)['SecurityGroups']
        old_sg_ids = [sg['GroupId'] for sg in sgs]

        # Get list of tagged ENIs
        enis = ec2_client.describe_network_interfaces(Filters=filters)['NetworkInterfaces']
        eni_ids = [eni['NetworkInterfaceId'] for eni in enis]

        # Anything really changed? Take a hash of things that can change and compare with previous hash...
        metadata_source = ''.join(sorted(INGRESS_PORTS + [str(total_sgs_rqd)] + eni_ids + svc_ranges)).encode()
        metadata_hash_now = hashlib.md5(metadata_source).hexdigest()[:5]
        metadata_hash_before = sgs[0]['GroupName'].split(' ')[1] if len(sgs) else None
        if metadata_hash_now == metadata_hash_before:
            logging.info(f"Skipping replacing SGs as there's no change in: {SERVICE} IP ranges, Ports, SGs required, and tagged ENIs.")
            continue

        # Create SGs sufficient for CIDRs and port-ranges and tag them
        new_sgs = []
        for i in range(total_sgs_rqd):
            SG_NAME = f'{NAME} {metadata_hash_now} {i+1}-of-{total_sgs_rqd} @{sg_label}s'
            new_sg = ec2_client.create_security_group(Description=SG_NAME, GroupName=SG_NAME, VpcId=vpc_id, DryRun=False)
            new_sgs.append(new_sg['GroupId'])
        ec2_client.create_tags(Resources=new_sgs, Tags=[{'Key':'PREFIX_NAME', 'Value':NAME}])
        logging.info(f'Created {total_sgs_rqd} new SGs {*new_sgs,}')

        # Add chunks of rules to each SG
        for i, sg in enumerate(new_sgs):
            chunk = rules[ i * max_rules_per_sg : (i+1) * max_rules_per_sg ]
            ec2_client.authorize_security_group_ingress(GroupId=sg, IpPermissions=chunk)
            logging.info(f'Added {len(chunk)} ingress rules to SG {sg}')

        # Update ENIs replacing old with new SGs, persisting any 'other' attached SGs
        for eni in enis:
            # Get associated SGs where GroupName doesn't start with our tag name
            other_sgs = [eni_sg['GroupId'] for eni_sg in eni['Groups'] if eni_sg['GroupName'].find(NAME) != 0]

            # Bomb if too many SGs
            if total_sgs_rqd + len(other_sgs) > max_sgs_per_eni:
                raise Exception(f"Total SGs required:{total_sgs_rqd} + existing SGs:{len(other_sgs)} is greater than the allowed maximum SGs per ENI:{max_sgs_per_eni}")

            # Atomic swap of old for new SGs
            ec2_client.modify_network_interface_attribute(
                Groups = new_sgs + other_sgs,
                NetworkInterfaceId = eni['NetworkInterfaceId'] )

            logging.info(f"Attached new SGs to ENI ({eni['NetworkInterfaceId']}) and kept existing SGs {*other_sgs,}")

        # Finally, delete old SGs
        for sg in old_sg_ids:
            ec2_client.delete_security_group(GroupId=sg)
            logging.info(f'Deleted redundant SG {sg}')
