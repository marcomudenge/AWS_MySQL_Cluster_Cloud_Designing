import logging
from pprint import pp
from typing import Any, Dict, Optional
import os

import boto3
from botocore.exceptions import ClientError, WaiterError

logger = logging.getLogger(__name__)

class SecurityGroupWrapper:
    """Encapsulates Amazon Elastic Compute Cloud (Amazon EC2) security group actions."""

    def __init__(self, ec2_client: boto3.client, security_group: Optional[str] = None):
        """
        Initializes the SecurityGroupWrapper with an EC2 client and an optional security group ID.

        :param ec2_client: A Boto3 Amazon EC2 client. This client provides low-level
                           access to AWS EC2 services.
        :param security_group: The ID of a security group to manage. This is a high-level identifier
                               that represents the security group.
        """
        self.ec2_client = ec2_client
        self.security_groups = []

    @classmethod
    def from_client(cls) -> "SecurityGroupWrapper":
        """
        Creates a SecurityGroupWrapper instance with a default EC2 client.

        :return: An instance of SecurityGroupWrapper initialized with the default EC2 client.
        """
        ec2_client = boto3.client("ec2",
                                  region_name=os.environ.get("AWS_DEFAULT_REGION", "us-west-1"),
                                  aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID"),
                                  aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY"),
                                  aws_session_token=os.environ.get("AWS_SESSION_TOKEN")
                                  )
        return cls(ec2_client)

    def create(self, group_name: str, group_description: str) -> str:
        """
        Creates a security group in the default virtual private cloud (VPC) of the current account.

        :param group_name: The name of the security group to create.
        :param group_description: The description of the security group to create.
        :return: The ID of the newly created security group.
        :raise Handles AWS SDK service-level ClientError, with special handling for ResourceAlreadyExists
        """
        try:
            response = self.ec2_client.create_security_group(
                GroupName=group_name, Description=group_description
            )
            self.security_groups.append(response["GroupId"])
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceAlreadyExists":
                logger.error(
                    f"Security group '{group_name}' already exists. Please choose a different name."
                )
            raise
        else:
            return response["GroupId"]

    def exists(self, group_name) -> Optional[str]:
        """
        Retrieves the security group ID for the specified security group name.

        :param group_name: The name of the security group to retrieve.
        :return: The ID of the security group if found, otherwise None.
        """
        response = self.ec2_client.describe_security_groups(Filters=[{"Name": "group-name", "Values": [group_name]}])
        if response["SecurityGroups"]:
            security_group = response["SecurityGroups"][0]["GroupId"]
            return security_group
        else:
            return None

    def retrieve(self, group_name, ingress_ip) -> Optional[str]:
        """
        Retrieves the security group ID for the specified security group name.

        :param group_name: The name of the security group to retrieve.
        :return: The ID of the security group if found, otherwise None.
        """
        response = self.ec2_client.describe_security_groups(Filters=[{"Name": "group-name", "Values": [group_name]}])
        if response["SecurityGroups"]:
            security_group = response["SecurityGroups"][0]["GroupId"]
            print(f"Retrieved security group '{security_group}'")

            # Check if the ip is already authorized for SSH/22 and TCP/80 connections
            ip_permissions = response["SecurityGroups"][0]["IpPermissions"]

            tcp_22 = False
            for ip_permission in ip_permissions:
                if (ip_permission["FromPort"] == 22) and (f"{ingress_ip}/32" in [ip_range["CidrIp"] for ip_range in ip_permission["IpRanges"]]):
                    print(f"Security group '{security_group}' already has the specified rule.")
                    tcp_22 = True
            
            if not tcp_22:
                print(f"Authorizing ingress for SSH/22 to IP {ingress_ip}")
                self.authorize_ingress(ingress_ip, [
                    {
                        # SSH ingress open to only the specified IP address.
                        "IpProtocol": "tcp",
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpRanges": [{"CidrIp": f"{ingress_ip}/32"}]
                    }
                ])

            self.security_groups.append(security_group)
            
            return security_group
        else:
            return None

    def authorize_ingress(self, sg_group_name:str, ip_permissions = None) -> Optional[Dict[str, Any]]:
        """
        Adds a rule to the security group to allow access to SSH.

        :param ingress_ip: The IP address that is granted inbound access to connect
                               to port 22 over TCP, used for SSH and port 8000 for web server.
        :return: The response to the authorization request. The 'Return' field of the
                 response indicates whether the request succeeded or failed, or None if no security group is set.
        :raise Handles AWS SDK service-level ClientError, with special handling for ResourceAlreadyExists
        """
        sg_group_id = self.exists(sg_group_name)

        response = self.ec2_client.describe_security_groups(Filters=[{"Name": "group-name", "Values": [sg_group_name]}])
        if response["SecurityGroups"]:
            # Check if the ip is already authorized for SSH/22 and TCP/80 connections
            existing_permissions = response["SecurityGroups"][0]["IpPermissions"]

            for ip_permission in ip_permissions:

                existing_permission_found = False
                for existing_permission in existing_permissions:
                    if (existing_permission["FromPort"] == ip_permission["FromPort"]) and \
                        (existing_permission["ToPort"] == ip_permission["ToPort"]) and \
                        (existing_permission["IpProtocol"] == ip_permission["IpProtocol"]) and \
                        (ip_permission["IpRanges"][0]["CidrIp"] in [ip_range["CidrIp"] for ip_range in existing_permission["IpRanges"]]):
                        print(f"Security group '{sg_group_name}' already has the permission for {ip_permission['IpProtocol']}/{ip_permission['FromPort']}/{ip_permission['ToPort']}/{ip_permission['IpRanges']}")
                        existing_permission_found = True

                if not existing_permission_found:
                    try:
                        response = self.ec2_client.authorize_security_group_ingress(
                            GroupId=sg_group_id, IpPermissions=[ip_permission]
                        )
                    except ClientError as err:
                        if err.response["Error"]["Code"] == "InvalidPermission.Duplicate":
                            logger.error(
                                f"Security group '{sg_group_id}' already has the specified rule."
                            )
                        raise
                    else:
                        return response
                    
    def describe(self, security_group_id: Optional[str] = None) -> bool:
        """
        Displays information about the specified security group or all security groups if no ID is provided.

        :param security_group_id: The ID of the security group to describe.
                                  If None, an open search is performed to describe all security groups.
        :returns: True if the description is successful.
        :raises ClientError: If there is an error describing the security group(s), such as an invalid security group ID.
        """
        try:
            paginator = self.ec2_client.get_paginator("describe_security_groups")

            if security_group_id is None:
                # If no ID is provided, return all security groups.
                page_iterator = paginator.paginate()
            else:
                page_iterator = paginator.paginate(GroupIds=[security_group_id])

            for page in page_iterator:
                for security_group in page["SecurityGroups"]:
                    print(f"Security group: {security_group['GroupName']}")
                    print(f"\tID: {security_group['GroupId']}")
                    print(f"\tVPC: {security_group['VpcId']}")
                    if security_group["IpPermissions"]:
                        print("Inbound permissions:")
                        pp(security_group["IpPermissions"])

            return True
        except ClientError as err:
            logger.error("Failed to describe security group(s).")
            if err.response["Error"]["Code"] == "InvalidGroup.NotFound":
                logger.error(
                    f"Security group {security_group_id} does not exist "
                    f"because the specified security group ID was not found."
                )
            raise

    def delete(self, security_group_id: str) -> bool:
        """
        Deletes the specified security group.

        :param security_group_id: The ID of the security group to delete. Required.

        :returns: True if the deletion is successful.
        :raises ClientError: If the security group cannot be deleted due to an AWS service error.
        """
        try:
            self.ec2_client.delete_security_group(GroupId=security_group_id)
            logger.info(f"Successfully deleted security group '{security_group_id}'")
            return True
        except ClientError as err:
            logger.error(f"Deletion failed for security group '{security_group_id}'")
            error_code = err.response["Error"]["Code"]

            if error_code == "InvalidGroup.NotFound":
                logger.error(
                    f"Security group '{security_group_id}' cannot be deleted because it does not exist."
                )
            elif error_code == "DependencyViolation":
                logger.error(
                    f"Security group '{security_group_id}' cannot be deleted because it is still in use."
                    " Verify that it is:"
                    "\n\t- Detached from resources"
                    "\n\t- Removed from references in other groups"
                    "\n\t- Removed from VPC's as a default group"
                )
            raise

    def delete_all(self) -> None:
        """
        Deletes all security groups in the current account.

        :raises ClientError: If there is an error in deleting the security groups.
        """
        try:
            response = self.ec2_client.describe_security_groups()
            security_groups = response.get("SecurityGroups", [])

            for security_group in security_groups:
                self.delete(security_group["GroupId"])
        except ClientError as err:
            logger.error(f"Failed to delete security groups: {str(err)}")
            raise