#!/bin/bash

unset AWS_ACCESS_KEY_ID
unset AWS_SECRET_ACCESS_KEY
unset AWS_REGION
export AWS_PROFILE=azohaib-cl
ami="resolve:ssm:/aws/service/canonical/ubuntu/server/22.04/stable/current/amd64/hvm/ebs-gp2/ami-id"

echo "Launching quix-client-final in us-west-1, quix-proxy-final and quix-server-final in us-east-1"

setup_region() {
	local region=$1

	echo ""
	echo "=== Setting up infrastructure in $region ==="

	aws ec2 import-key-pair --region $region --key-name "quix-keypair" --public-key-material fileb://~/.ssh/aws-quix.pub 2>/dev/null

	vpc=$(aws ec2 describe-vpcs --region $region --query 'Vpcs[0].VpcId' --output text)

	if [ "$vpc" = "None" ]; then
		echo "Creating VPC..."
		vpc=$(aws ec2 create-vpc \
			--cidr-block 10.0.0.0/16 \
			--region $region \
			--query Vpc.VpcId \
			--output text)
	fi

	echo "VPC: $vpc"

	# Get VPC IPv4 CIDR for subnet creation
	vpc_cidr=$(aws ec2 describe-vpcs \
	  --vpc-ids "$vpc" \
	  --region "$region" \
	  --query 'Vpcs[0].CidrBlock' \
	  --output text)
	echo "VPC CIDR: $vpc_cidr"

	existing_vpc_ipv6=$(aws ec2 describe-vpcs \
	  --vpc-ids "$vpc" \
	  --region "$region" \
	  --query 'Vpcs[0].Ipv6CidrBlockAssociationSet[?Ipv6CidrBlockState.State==`associated`].Ipv6CidrBlock | [0]' \
	  --output text)

	if [ "$existing_vpc_ipv6" = "None" ] || [ -z "$existing_vpc_ipv6" ]; then
	  echo "Associating an Amazon-provided IPv6 CIDR block..."
	  aws ec2 associate-vpc-cidr-block \
	    --amazon-provided-ipv6-cidr-block \
	    --vpc-id "$vpc" \
	    --region "$region"

	  sleep 10

	  existing_vpc_ipv6=$(aws ec2 describe-vpcs \
	    --vpc-ids "$vpc" \
	    --region "$region" \
	    --query 'Vpcs[0].Ipv6CidrBlockAssociationSet[?Ipv6CidrBlockState.State==`associated`].Ipv6CidrBlock | [0]' \
	    --output text)
	fi

	# Derive a /64 from the VPC's /56
	subnet_ipv6_cidr="${existing_vpc_ipv6%00::/56}00::/64"
	echo "Subnet IPv6 CIDR: $subnet_ipv6_cidr"

	subnet=$(aws ec2 describe-subnets \
	  --filters "Name=vpc-id,Values=$vpc" \
	  --region "$region" \
	  --query 'Subnets[0].SubnetId' \
	  --output text)

	if [ "$subnet" = "None" ]; then
		echo "Creating Subnet..."
		subnet=$(aws ec2 create-subnet \
			--vpc-id $vpc \
			--cidr-block "$vpc_cidr" \
			--ipv6-cidr-block "$subnet_ipv6_cidr" \
			--region $region \
			--query "Subnet.SubnetId" \
			--output text)

		# Check if internet gateway already exists for this VPC
		gwid=$(aws ec2 describe-internet-gateways \
			--filters "Name=attachment.vpc-id,Values=$vpc" \
			--region $region \
			--query 'InternetGateways[0].InternetGatewayId' \
			--output text)

		if [ "$gwid" = "None" ] || [ -z "$gwid" ]; then
			gwid=$(aws ec2 create-internet-gateway --region $region --query InternetGateway.InternetGatewayId --output text)
			echo "Made gateway $gwid"
			aws ec2 attach-internet-gateway --region $region --vpc-id $vpc --internet-gateway-id $gwid
		else
			echo "Using existing gateway $gwid"
		fi

		rtid=$(aws ec2 create-route-table --region $region --vpc-id $vpc --query RouteTable.RouteTableId --output text)
		echo "Made route table ID $rtid"
		aws ec2 create-route --route-table-id $rtid --destination-cidr-block 0.0.0.0/0 --gateway-id $gwid --region $region
		aws ec2 create-route --route-table-id "$rtid" --destination-ipv6-cidr-block ::/0 --gateway-id "$gwid" --region "$region"

		aws ec2 associate-route-table --region $region --subnet-id $subnet --route-table-id $rtid

		aws ec2 modify-subnet-attribute \
			--subnet-id $subnet \
			--assign-ipv6-address-on-creation \
			--region $region
	fi

	echo "Subnet: $subnet"

	SECURITY_GROUP_ID=$(aws ec2 describe-security-groups \
			--region $region \
			--filters Name=group-name,Values=quix-security-group \
			--query 'SecurityGroups[0].GroupId' \
			--output text)

	if [ "$SECURITY_GROUP_ID" = "None" ]; then
		aws ec2 create-security-group --region $region --group-name quix-security-group --description "Allow all traffic" --vpc-id $vpc

		SECURITY_GROUP_ID=$(aws ec2 describe-security-groups \
			--region $region \
			--filters Name=group-name,Values=quix-security-group \
			--query 'SecurityGroups[0].GroupId' \
			--output text)

		aws ec2 authorize-security-group-ingress \
			--group-id $SECURITY_GROUP_ID \
			--protocol all \
			--port -1 \
			--cidr 0.0.0.0/0 \
			--region $region

		aws ec2 authorize-security-group-ingress \
		    --group-id "$SECURITY_GROUP_ID" \
		    --ip-permissions IpProtocol=all,Ipv6Ranges='[{CidrIpv6=::/0}]' \
		    --region "$region"
	fi

	echo "Security Group: $SECURITY_GROUP_ID"
}

launch_instance() {
	local region=$1
	local name=$2
	local inst_type=$3

	echo ""
	echo "Launching $name ($inst_type) in $region..."

	id=$(aws ec2 run-instances \
		--image-id $ami \
		--region $region \
		--subnet-id $subnet \
		--instance-type $inst_type \
		--security-group-ids $SECURITY_GROUP_ID \
		--tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$name}]" \
		--network-interfaces "{\"SubnetId\":\"$subnet\",\"AssociatePublicIpAddress\":true,\"DeviceIndex\":0}" \
		--block-device-mappings "[{\"DeviceName\":\"/dev/sda1\",\"Ebs\":{\"VolumeSize\":64,\"DeleteOnTermination\":true}}]" \
		--key-name quix-keypair \
		--query 'Instances[].InstanceId' \
		--output text)

	echo "  Instance ID: $id"

	sleep 5

	ip=$(aws ec2 describe-instances \
		--instance-ids $id \
		--region $region \
		--query 'Reservations[0].Instances[0].PublicIpAddress' \
		--output text)

	eni=$(aws ec2 describe-instances \
		--instance-ids $id \
		--region $region \
		--query 'Reservations[].Instances[].NetworkInterfaces[].NetworkInterfaceId' \
		--output text)

	aws ec2 assign-ipv6-addresses \
		--region $region \
		--network-interface-id $eni \
		--ipv6-prefix-count 1

	ipv6prefix=$(aws ec2 describe-network-interfaces \
		--network-interface-ids "$eni" \
		--region $region \
		--query "NetworkInterfaces[].Ipv6Prefixes[].Ipv6Prefix" \
		--output text)

	public_ipv6=$(aws ec2 describe-network-interfaces \
		--network-interface-ids "$eni" \
		--region "$region" \
		--query "NetworkInterfaces[].Ipv6Addresses[].Ipv6Address" \
		--output text)

	echo "  IPv4: $ip"
	echo "  IPv6: $public_ipv6"
	echo "  IPv6 Prefix: $ipv6prefix"
	echo "$region $id $ip $public_ipv6 $ipv6prefix $name" >> ./final_instances
}

# Setup us-west-1 and launch client
setup_region "us-west-1"
launch_instance "us-west-1" "quix-client-final" "c5.xlarge"

# Setup us-east-1 and launch proxy + server
setup_region "us-east-1"
launch_instance "us-east-1" "quix-proxy-final" "c5.xlarge"
launch_instance "us-east-1" "quix-server-final" "t3.medium"

echo ""
echo "Done. Instance details written to ./final_instances"
