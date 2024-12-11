import logging
import os
import tempfile
from typing import Optional, Union

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

class KeyPairWrapper:
    """
    Encapsulates Amazon Elastic Compute Cloud (Amazon EC2) key pair actions.
    This class provides methods to create, list, and delete EC2 key pairs.
    """

    def __init__(
        self,
        ec2_client: boto3.client,
        key_file_dir: None,
        key_pair: Optional[dict] = None,
    ):
        """
        Initializes the KeyPairWrapper with the specified EC2 client, key file directory,
        and an optional key pair.

        :param ec2_client: A Boto3 Amazon EC2 client. This client provides low-level
                           access to AWS EC2 services.
        :param key_file_dir: The folder where the private key information is stored.
                             This should be a secure folder.
        :param key_pair: A dictionary representing the Boto3 KeyPair object.
                         This is a high-level object that wraps key pair actions. Optional.
        """
        self.ec2_client = ec2_client
        self.key_pair = key_pair
        self.key_file_path: Optional[str] = None
        self.key_file_dir = os.environ.get("KEY_FILE_DIR", key_file_dir)

    @classmethod
    def from_client(cls) -> "KeyPairWrapper":
        """
        Class method to create an instance of KeyPairWrapper using a new EC2 client
        and a temporary directory for storing key files.

        :return: An instance of KeyPairWrapper.
        """
        ec2_client = boto3.client("ec2",
                                  region_name=os.environ.get("AWS_DEFAULT_REGION", "us-west-1"),
                                  aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID"),
                                  aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY"),
                                  aws_session_token=os.environ.get("AWS_SESSION_TOKEN")
                                  )
        
        key_file_dir = os.path.join(os.getcwd(), "keys")
        return cls(ec2_client, key_file_dir)

    def create(self, key_name: str) -> dict:
        """
        Creates a key pair that can be used to securely connect to an EC2 instance.
        The returned key pair contains private key information that cannot be retrieved
        again. The private key data is stored as a .pem file.

        :param key_name: The name of the key pair to create.
        :return: A dictionary representing the Boto3 KeyPair object that represents the newly created key pair.
        :raises ClientError: If there is an error in creating the key pair, for example, if a key pair with the same name already exists.
        """
        try:
            response = self.ec2_client.create_key_pair(KeyName=key_name)
            self.key_pair = response
            self.key_file_path = os.path.join(
                self.key_file_dir, f"{self.key_pair['KeyName']}.pem"
            )

            # Make directory if it does not exist
            if not os.path.exists(self.key_file_dir):
                os.makedirs(self.key_file_dir)

            # Create the an empty file to store the private key
            with open(self.key_file_path, "w") as key_file:
                key_file.write(self.key_pair["KeyMaterial"])

        except ClientError as err:
            if err.response["Error"]["Code"] == "InvalidKeyPair.Duplicate":
                logger.error(
                    f"A key pair called {key_name} already exists. "
                    "Please choose a different name for your key pair "
                    "or delete the existing key pair before creating."
                )
            raise
        else:
            return self.key_pair
        
    def exists(self, key_name: str) -> dict:
        """
        Retrieves an existing key pair by its name.

        :param key_name: The name of the key pair to retrieve.
        :return: A dictionary representing the Boto3 KeyPair object that represents the retrieved key pair.
        :raises ClientError: If there is an error in retrieving the key pair, for example, if the key pair does not exist.
        """
        response = self.ec2_client.describe_key_pairs(Filters=[{"Name": "key-name", "Values": [key_name]}])
        key_pairs = response.get("KeyPairs", [])
        if key_pairs:
            key_pair = key_pairs[0]
            key_file_path = os.path.join(
                self.key_file_dir, f"{key_pair['KeyName']}.pem"
            )

            # Check if the key file already exists
            if not os.path.exists(key_file_path):
                return None

            return key_pair
        else:
            return None
        
    def retrieve(self, key_name: str) -> dict:
        """
        Retrieves an existing key pair by its name.

        :param key_name: The name of the key pair to retrieve.
        :return: A dictionary representing the Boto3 KeyPair object that represents the retrieved key pair.
        :raises ClientError: If there is an error in retrieving the key pair, for example, if the key pair does not exist.
        """
        response = self.ec2_client.describe_key_pairs(Filters=[{"Name": "key-name", "Values": [key_name]}])
        key_pairs = response.get("KeyPairs", [])
        if key_pairs:
            self.key_pair = key_pairs[0]
            self.key_file_path = os.path.join(
                self.key_file_dir, f"{self.key_pair['KeyName']}.pem"
            )

            # Check if the key file already exists
            if not os.path.exists(self.key_file_path):
                return None
            
            print(f"Retrieved key pair {key_name}")

            return self.key_pair
        else:
            return None

    def list(self, limit: Optional[int] = None) -> None:
        """
        Displays a list of key pairs for the current account.

        WARNING: Results are not paginated.

        :param limit: The maximum number of key pairs to list. If not specified,
                      all key pairs will be listed.
        :raises ClientError: If there is an error in listing the key pairs.
        """
        try:
            response = self.ec2_client.describe_key_pairs()
            key_pairs = response.get("KeyPairs", [])

            if limit:
                key_pairs = key_pairs[:limit]

            for key_pair in key_pairs:
                logger.info(
                    f"Found {key_pair['KeyType']} key '{key_pair['KeyName']}' with fingerprint:"
                )
                logger.info(f"\t{key_pair['KeyFingerprint']}")
        except ClientError as err:
            logger.error(f"Failed to list key pairs: {str(err)}")
            raise

    def delete(self, key_name: str) -> bool:
        """
        Deletes a key pair by its name.

        :param key_name: The name of the key pair to delete.
        :return: A boolean indicating whether the deletion was successful.
        :raises ClientError: If there is an error in deleting the key pair, for example,
                             if the key pair does not exist.
        """
        try:
            self.ec2_client.delete_key_pair(KeyName=key_name)
            logger.info(f"Successfully deleted key pair: {key_name}")
            self.key_pair = None
            return True
        except self.ec2_client.exceptions.ClientError as err:
            logger.error(f"Deletion failed for key pair: {key_name}")
            error_code = err.response["Error"]["Code"]
            if error_code == "InvalidKeyPair.NotFound":
                logger.error(
                    f"The key pair '{key_name}' does not exist and cannot be deleted. "
                    "Please verify the key pair name and try again."
                )
            raise