import logging
import time
import csv
import urllib.request
import uuid
import os
import paramiko
import requests

import boto3
from alive_progress import alive_bar
from rich.console import Console


from instance import EC2InstanceWrapper
from keypair import KeyPairWrapper
from security_group import SecurityGroupWrapper

logger = logging.getLogger(__name__)
console = Console()

# Read AWS credentials from environment file AWSaccess.txt
with open("AWS_access.txt", "r") as file:
    AWS_ACCESS_KEY_ID = file.readline().split("aws_access_key_id=")[1].strip()
    AWS_SECRET_ACCESS_KEY = file.readline().split("aws_secret_access_key=")[1].strip()
    AWS_SESSION_TOKEN = file.readline().split("aws_session_token=")[1].strip()

# Verify that the AWS credentials are set
if not AWS_ACCESS_KEY_ID or not AWS_SECRET_ACCESS_KEY or not AWS_SESSION_TOKEN:
    console.print(
        "AWS credentials not found. Please ensure that the 'AWSaccess.txt' file contains the necessary credentials.",
        style="bold red",
    )
    exit(1)

INSTANCE_AMI = 'ami-0866a3c8686eaeeba' # Ubuntu Server 24.04 LTS (HVM), SSD Volume Type
INSTANCE_COUNT = 3
INSTANCE_TYPE = 't2.micro'

DB_INSTANCES_NAMES = ["db1", "db2", "db3"]
DB_INSTANCES_AMI = 'ami-0866a3c8686eaeeba'
DB_INSTANCES_TYPE = ['t2.micro', 't2.micro', 't2.micro']

PROXY_INSTANCE_NAME = ["proxy"]
PROXY_INSTANCE_TYPE = ['t2.large']
PROXY_INSTANCE_AMI = 'ami-0866a3c8686eaeeba'

TRUSTED_HOSTS_INSTANCES_NAMES = ["trusted"]
TRUSTED_HOSTS_INSTANCES_TYPE = ['t2.large']
TRUSTED_HOSTS_INSTANCES_AMI = 'ami-0866a3c8686eaeeba'

GATEKEEPER_INSTANCES_NAMES = ["gatekeeper"]
GATEKEEPER_INSTANCES_TYPE = ['t2.large']
GATEKEEPER_INSTANCES_AMI = 'ami-0866a3c8686eaeeba'

# Create a list of dictionaries with the instance names and types
DB_CLUSTER = [ {"Name": name, "Type": type} for name, type in zip(DB_INSTANCES_NAMES, DB_INSTANCES_TYPE)]
PROXY = [ {"Name": name, "Type": type} for name, type in zip(PROXY_INSTANCE_NAME, PROXY_INSTANCE_TYPE)]
GATEKEEPER = [ {"Name": name, "Type": type} for name, type in zip(GATEKEEPER_INSTANCES_NAMES, GATEKEEPER_INSTANCES_TYPE)]
TRUSTED_HOST = [ {"Name": name, "Type": type} for name, type in zip(TRUSTED_HOSTS_INSTANCES_NAMES, TRUSTED_HOSTS_INSTANCES_TYPE)]

os.environ['INSTANCE_AMI'] = INSTANCE_AMI
os.environ['INSTANCE_COUNT'] = str(INSTANCE_COUNT)
os.environ['INSTANCE_TYPE'] = INSTANCE_TYPE

os.environ['AWS_DEFAULT_REGION'] = "us-east-1"
os.environ['AWS_ACCESS_KEY_ID'] = AWS_ACCESS_KEY_ID
os.environ['AWS_SECRET_ACCESS_KEY'] = AWS_SECRET_ACCESS_KEY
os.environ['AWS_SESSION_TOKEN'] = AWS_SESSION_TOKEN

os.environ['KEY_FILE_DIR'] = os.path.join(os.getcwd(), "keys")
INSTANCE_NAME = "MapReduce"

console = Console()

class DbClusterScenario:
    """
    A scenario that demonstrates how to use Boto3 to manage Amazon EC2 resources.
    Covers creating a key pair, security group, launching an instance, associating
    an Elastic IP, and cleaning up resources.
    """

    def __init__(
        self,
        inst_wrapper: EC2InstanceWrapper,
        key_wrapper: KeyPairWrapper,
        sg_wrapper: SecurityGroupWrapper,
        remote_exec: bool = False
    ):
        """
        Initializes the MapReduceScenario with the necessary AWS service wrappers.

        :param inst_wrapper: Wrapper for EC2 instance operations.
        :param key_wrapper: Wrapper for key pair operations.
        :param sg_wrapper: Wrapper for security group operations.
        :param ssm_client: Boto3 client for accessing SSM to retrieve AMIs.
        :param remote_exec: Flag to indicate if the scenario is running in a remote execution
                            environment. Defaults to False. If True, the script won't prompt
                            for user interaction.
        """
        self.ec2_client = boto3.client("ec2")
        self.inst_wrapper = inst_wrapper
        self.key_wrapper = key_wrapper
        self.sg_wrapper = sg_wrapper
        self.remote_exec = remote_exec

    def create_and_list_key_pairs(self, key_name="DbScenario-KP") -> None:
        """
        Creates an RSA key pair for SSH access to the EC2 instance and lists available key pairs.
        """

        # Check if the key pair already exists
        if self.key_wrapper.exists(key_name):
            console.print(f"Key pair {key_name} already exists.")
            self.key_wrapper.retrieve(key_name)
            return

        with alive_bar(1, title=f"Creating Key Pair: {key_name}") as bar:
            self.key_wrapper.create(key_name)
            time.sleep(1) 
            bar()

        console.print(f"- **Private Key Saved to**: {self.key_wrapper.key_file_path}\n")

    def create_security_group(self, name="DbScenario-SG", ip_permissions=None) -> None:
        """
        Creates a security group that controls access to the EC2 instance and adds a rule
        to allow SSH access from the user's current public IP address.
        """

        # Check if the security group already exists
        if self.sg_wrapper.exists(name):
            console.print(f"Security group {name} already exists.")
            ip_response = urllib.request.urlopen("http://checkip.amazonaws.com")
            current_ip_address = ip_response.read().decode("utf-8").strip()
            self.sg_wrapper.retrieve(name, current_ip_address)
            return

        with alive_bar(1, title=f"Creating Security Group: {name}") as bar:
            self.sg_wrapper.create(
                name, "Instances security"
            )
            time.sleep(1)
            bar()

        console.print(f"- **Security Group ID**: {self.sg_wrapper.exists(name)}")

        with alive_bar(1, title="Updating Security Group Rules") as bar:
            response = self.sg_wrapper.authorize_ingress(name, ip_permissions=ip_permissions)
            time.sleep(0.4)
            if response and response.get("Return"):
                console.print("- **Security Group Rules Updated**.")
            else:
                console.print(
                    "- **Error**: Couldn't update security group rules.",
                    style="bold red",
                )
            bar()

        self.sg_wrapper.describe(self.sg_wrapper.exists(name))

    def create_security_groups(self):
        
        ip_response = urllib.request.urlopen("http://checkip.amazonaws.com")
        current_ip_address = ip_response.read().decode("utf-8").strip()
        base_ssh_permissions = [
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": f"{current_ip_address}/32"}, {"CidrIp": "18.206.107.24/29"}],
            }
        ]

        cluster_sg_id = self.sg_wrapper.exists("DbScenario-SG-cluster")
        if cluster_sg_id:
            console.print(f"Found security group ID: {cluster_sg_id}")
            self.sg_wrapper.retrieve(cluster_sg_id, current_ip_address)
        else:
            self.create_security_group("DbScenario-SG-cluster", ip_permissions=base_ssh_permissions)

        proxy_sg_id = self.sg_wrapper.exists("DbScenario-SG-proxy")
        if proxy_sg_id:
            console.print(f"Found security group ID: {proxy_sg_id}")
            self.sg_wrapper.retrieve(proxy_sg_id, current_ip_address)
        else:
            self.create_security_group("DbScenario-SG-proxy", ip_permissions=base_ssh_permissions)

        trusted_sg_id = self.sg_wrapper.exists("DbScenario-SG-trusted")
        if trusted_sg_id:
            console.print(f"Found security group ID: {trusted_sg_id}")
            self.sg_wrapper.retrieve(trusted_sg_id, current_ip_address)
        else:
            self.create_security_group("DbScenario-SG-trusted", ip_permissions=base_ssh_permissions)
        
        gatekeeper_sg_id = self.sg_wrapper.exists("DbScenario-SG-gatekeeper")
        if gatekeeper_sg_id:
            console.print(f"Found security group ID: {gatekeeper_sg_id}")
            self.sg_wrapper.retrieve(gatekeeper_sg_id, current_ip_address)
        else:
            self.create_security_group("DbScenario-SG-gatekeeper", ip_permissions=base_ssh_permissions)

    def create_instance(self, inst_type_choice, sg_name) -> None:
        """
        Launches an EC2 instance using an specific AMI and the created key pair
        and security group. Displays instance details and SSH connection information.
        """

        with alive_bar(1, title="Creating Instances") as bar:
            self.inst_wrapper.create(
                INSTANCE_AMI,
                inst_type_choice["InstanceType"],
                self.key_wrapper.key_pair["KeyName"],
                [self.sg_wrapper.exists(sg_name)],
            )
            time.sleep(18)
            bar()

    def create_named_instance(self, instance_name="Default", instance_ami=INSTANCE_AMI ,instance_type=INSTANCE_TYPE, sg_name="DbScenario-SG") -> None:
        """
        Launches an EC2 instance using an specific AMI and the created key pair
        and security group. Displays instance details and SSH connection information.
        """
        console.print(f"Creating an instance with name: {instance_name}", style="bold cyan")
        console.print(
            "Let's create an instance from a specified AMI: {} and instance type : {}".format(instance_ami, instance_type)
        )

        inst_types = self.inst_wrapper.get_instance_types("x86_64")

        inst_type_choice = None
        for inst_type in inst_types:
            if inst_type["InstanceType"] == instance_type:
                console.print(f"- Found requested instance type: {inst_type['InstanceType']}")
                inst_type_choice = inst_type
                break
        
        if inst_type_choice is None:
            console.print(f"- Requested instance type '{instance_type}' not found.")
            return

        console.print("Creating an instance now...")

        with alive_bar(1, title="Creating Instances") as bar:
            self.inst_wrapper.create(
                INSTANCE_AMI,
                inst_type_choice["InstanceType"],
                self.key_wrapper.key_pair["KeyName"],
                [self.sg_wrapper.exists(sg_name)],
                instance_name
            )
            time.sleep(18)
            bar()

        #self.inst_wrapper.add_tag(self.inst_wrapper.instances[0]["InstanceId"], "Name", instance_name)

        self.inst_wrapper.display()

        #self._display_ssh_info()

    def retrieve_instance(self, instance_name=INSTANCE_NAME)-> bool:
        """
        Retrieves an instance with a specified name.

        :param instance_name: The name of the instance to retrieve.
        :return: The instance with the specified name, or None if no instance is found.
        """
        console.print("\n**Checking for existing ressources**", style="bold cyan")

        instance = self.inst_wrapper.exists(instance_name)
        if not instance:
            console.print(f"Instance with name {instance_name} not found")
            return False
        
        # Try to retrieve the keypair
        key_name = instance["KeyName"]
        key = self.key_wrapper.exists(key_name)
        if key:
            console.print(f"Found key pair {key_name}")
        else:
            console.print(f"Key pair {key_name} not found")
        
        # Try to retrieve the security group
        sg_name = instance["SecurityGroups"][0]["GroupName"]
        sg = self.sg_wrapper.exists(sg_name)
        if sg:
            console.print(f"Found security group {sg_name}")
        else:
            console.print(f"Security group {sg_name} not found")

        if instance and key and sg:
            self.key_wrapper.retrieve(key_name)
            ip_response = urllib.request.urlopen("http://checkip.amazonaws.com")
            current_ip_address = ip_response.read().decode("utf-8").strip()
            self.sg_wrapper.retrieve(sg_name, current_ip_address)
            self.inst_wrapper.retrieve(instance_name)
            return True
        else:
            console.print("One or more resources not found")
            self.inst_wrapper.remove_tag(instance["InstanceId"], "Name")

        return False
        
    def _display_ssh_info(self) -> None:
        """
        Displays SSH connection information for the user to connect to the EC2 instance.
        Handles the case where the instance does or does not have an associated public IP address.
        """
        if self.inst_wrapper.instances:
            for instance in self.inst_wrapper.instances:
                instance_id = instance["InstanceId"]

                waiter = self.inst_wrapper.ec2_client.get_waiter("instance_running")
                console.print(
                    "Waiting for the instance to be in a running state with a public IP...",
                    style="bold cyan",
                )

                with alive_bar(1, title="Waiting for Instance to Start") as bar:
                    waiter.wait(InstanceIds=[instance_id])
                    time.sleep(1)
                    bar()

                public_ip = self.get_public_ip(instance_id)
                if public_ip:
                    console.print(
                        "\nTo connect via SSH, open another command prompt and run the following command:",
                        style="bold cyan",
                    )
                    console.print(
                        f"\tssh -i {self.key_wrapper.key_file_path} ec2-user@{public_ip}"
                    )
                else:
                    console.print(
                        "Instance does not have a public IP address assigned.",
                        style="bold red",
                    )
        else:
            console.print(
                "No instance available to retrieve public IP address.",
                style="bold red",
            )
        
    def get_public_ip(self, instance_id):
        instance = self.inst_wrapper.ec2_client.describe_instances(
            InstanceIds=[instance_id]
            )["Reservations"][0]["Instances"][0]
        return instance.get("PublicIpAddress")
    
    def execute_ssh_command(self, ssh: paramiko.SSHClient, command: str) -> bool:
        """Helper function to execute SSH commands."""
        session = ssh.get_transport().open_session()
        session.get_pty()
        session.exec_command(command)
    
        print(f"Executing: {command}")

        stderr = session.makefile_stderr("r", -1)

        exit_status = session.recv_exit_status()
        
        if exit_status != 0:
            error_message = stderr.read().decode()
            print(f"Command failed: {command}, Error: {error_message}")
            return False

        return True

    def execute_ssh_command_background_safe(self, ssh: paramiko.SSHClient, command: str) -> bool:
        """Helper function to execute SSH commands in the background."""
        print(f"Executing: {command}")
        stdin, stdout, stderr = ssh.exec_command(command)
        exit_status = stdout.channel.recv_exit_status()
        if exit_status != 0:
            print(f"Command failed: {command}, Error: {stderr.read().decode()}")
            return False
        return True
    
    def scp_file_from_remote(self, key_path, public_ip, remote_file, local_file):
        """
        Downloads a file from a remote server using SCP.
        """
        scp_command = f"scp -o StrictHostKeyChecking=no -i {key_path} ubuntu@{public_ip}:{remote_file} {local_file}"
        os.system(scp_command)

        #Check if the file was downloaded
        if os.path.exists(local_file):
            console.print(f"Downloaded {remote_file} to {local_file}")
        else:
            console.print(f"Failed to download {remote_file} to {local_file}")
            return False
        return True
    
    def scp_dir_to_remote(self, key_path, public_ip, local_dir, remote_dir):
        """
        Upload a file to a remote server using SCP.
        """
        scp_command = f"scp -o StrictHostKeyChecking=no -i {key_path} -r {local_dir} ubuntu@{public_ip}:{remote_dir}"
        os.system(scp_command)
        
    def setup_mysql(self, instance_id, instance_name):
        """
        Set up MySQL on the EC2 instances
        """
        console.print(f"\n**Setting up instance {instance_name}**", style="bold cyan")

        # Check if tag 'Deployed' is already set on the instance
        instance = self.inst_wrapper.ec2_client.describe_instances(
            InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]
        tags = instance.get("Tags")
        if tags:
            for tag in tags:
                if tag["Key"] == "Deployed" and tag["Value"] == "True":
                    console.print(
                        f"Setup already done for instance {instance_id}."
                    )
                    return
                
        with open("./instance_startup_scripts/mysql_slave.txt", "r") as file:
            slave_commands = file.read()
        
        with open("./instance_startup_scripts/mysql_master.txt", "r") as file:
            master_commands = file.read()
    
        os.makedirs("benchmark_files", exist_ok=True)

        m_nodestatus_file = "~/master_node_status.txt"
        w_nodestatus_file = f"~/worker_node_status_{instance_name}.txt"
        local_m_nodestatus_file = "./benchmark_files/master_node_status.txt"
        local_w_nodestatus_file = f"./benchmark_files/worker_node_status_{instance_name}.txt"
        sysbench_file = "~/sysbench_results.txt"
        local_sysbench_file = f"./benchmark_files/sysbench_{instance_name}.txt"

        # Set the permission 400 to key_file_path
        os.chmod(self.key_wrapper.key_file_path, 0o400)
        os.chmod(os.path.dirname(self.key_wrapper.key_file_path), 0o700)

        public_ip = self.get_public_ip(instance_id)
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(
                hostname=public_ip, 
                username="ubuntu",
                key_filename=self.key_wrapper.key_file_path
            )

            instance_commands = None
            if instance_name == "db1":
                instance_commands = master_commands
                instance_commands = instance_commands.replace("BENCHMARK_FILE_VAR", sysbench_file)
                instance_commands = instance_commands.replace("M_NODESTATUS_FILE_VAR", m_nodestatus_file)
                instance_commands = instance_commands.split("\n")

            else:
                instance_commands = slave_commands

                db1_instance = self.inst_wrapper.exists("db1")
                if db1_instance:

                    with open(local_m_nodestatus_file, "r") as f:
                        file = f.readlines()
                    
                    db1_file = file[1].split("\t")[0].strip()
                    db1_position = file[1].split("\t")[1].strip()
                    
                    # Format the commands
                    instance_commands = instance_commands.replace("SLAVE_ID_VAR", str(int(instance_name[-1])))
                    instance_commands = instance_commands.replace("MASTER_IP_VAR", str(db1_instance["PrivateIpAddress"]))
                    instance_commands = instance_commands.replace("LOG_FILE_VAR", db1_file)
                    instance_commands = instance_commands.replace("LOG_POS_VAR", db1_position)
                    instance_commands = instance_commands.replace("BENCHMARK_FILE_VAR", sysbench_file)
                    instance_commands = instance_commands.replace("W_NODESTATUS_FILE_VAR", w_nodestatus_file)
                    instance_commands = instance_commands.split("\n")

            for command in instance_commands:
                if not self.execute_ssh_command(ssh, command):
                    break

            self.scp_file_from_remote(self.key_wrapper.key_file_path, public_ip, sysbench_file, local_sysbench_file)
            if instance_name == 'db1':
                self.scp_file_from_remote(self.key_wrapper.key_file_path, public_ip, m_nodestatus_file, local_m_nodestatus_file)
            else:
                self.scp_file_from_remote(self.key_wrapper.key_file_path, public_ip, w_nodestatus_file, local_w_nodestatus_file)
            
            # Set the tag 'Deployed' to 'True' on the instance
            self.inst_wrapper.add_tag(instance_id, "Deployed", "True")

            ssh.close()
                
        except paramiko.SSHException as e:
            print(f"SSH connection failed: {str(e)}")
        
        finally:
            ssh.close()

    def setup_proxy(self, instance_id):     
        """
        Set up the proxy
        """
        console.print(f"\n**Setting up proxy instance**", style="bold cyan")

        # Check if tag 'Deployed' is already set on the instance
        instance = self.inst_wrapper.ec2_client.describe_instances(
            InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]
        tags = instance.get("Tags")
        if tags:
            for tag in tags:
                if tag["Key"] == "Deployed" and tag["Value"] == "True":
                    console.print(
                        f"Setup already done for proxy instance."
                    )
                    return

        with open("./instance_startup_scripts/proxy.txt", "r") as file:
            proxy_commands = file.read()
        
        # Set the permission 400 to key_file_path
        os.chmod(self.key_wrapper.key_file_path, 0o400)
        os.chmod(os.path.dirname(self.key_wrapper.key_file_path), 0o700)

        public_ip = self.get_public_ip(instance_id)
        self.scp_dir_to_remote(self.key_wrapper.key_file_path, public_ip, "./logic", "~/")
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(
                hostname=public_ip, 
                username="ubuntu",
                key_filename=self.key_wrapper.key_file_path
            )

            db1_instance = self.inst_wrapper.exists("db1")
            if db1_instance:
                db1_private_ip = db1_instance["PrivateIpAddress"]

            db2_instance = self.inst_wrapper.exists("db2")
            if db2_instance:
                db2_private_ip = db2_instance["PrivateIpAddress"]

            db3_instance = self.inst_wrapper.exists("db3")
            if db3_instance:
                db3_private_ip = db3_instance["PrivateIpAddress"]

            proxy_commands = proxy_commands.replace("MASTER_IP_VAR", db1_private_ip)
            proxy_commands = proxy_commands.replace("SLAVE_1_IP_VAR", db2_private_ip)
            proxy_commands = proxy_commands.replace("SLAVE_2_IP_VAR", db3_private_ip)
            proxy_commands = proxy_commands.split("\n")

            for command in proxy_commands:
                if not self.execute_ssh_command_background_safe(ssh, command):
                    break

            # Set the tag 'Deployed' to 'True' on the instance
            self.inst_wrapper.add_tag(instance_id, "Deployed", "True")

            ssh.close()

        except paramiko.SSHException as e:
            print(f"SSH connection failed: {str(e)}")
        
        finally:
            ssh.close()

    def setup_trusted_host(self, instance_id):
        """
        Set up the trusted host
        """
        console.print(f"\n**Setting the trusted host instance**", style="bold cyan")

        # Check if tag 'Deployed' is already set on the instance
        instance = self.inst_wrapper.ec2_client.describe_instances(
            InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]
        tags = instance.get("Tags")
        if tags:
            for tag in tags:
                if tag["Key"] == "Deployed" and tag["Value"] == "True":
                    console.print(
                        f"Setup already done for trusted host instance."
                    )
                    return

        with open("./instance_startup_scripts/gatekeeper.txt", "r") as file:
            trusted_host_commands = file.read()

        # Set the permission 400 to key_file_path
        os.chmod(self.key_wrapper.key_file_path, 0o400)
        os.chmod(os.path.dirname(self.key_wrapper.key_file_path), 0o700)

        public_ip = self.get_public_ip(instance_id)
        self.scp_dir_to_remote(self.key_wrapper.key_file_path, public_ip, "./logic", "~/")
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(
                hostname=public_ip, 
                username="ubuntu",
                key_filename=self.key_wrapper.key_file_path
            )

            # Get the trusted instance IP
            proxy_instance = self.inst_wrapper.exists("proxy")
            if proxy_instance:
                proxy_ip = proxy_instance["PrivateIpAddress"]

            trusted_host_commands = trusted_host_commands.replace("TRUSTED_IP_VAR", proxy_ip)
            trusted_host_commands = trusted_host_commands.split("\n")

            for command in trusted_host_commands:
                if not self.execute_ssh_command_background_safe(ssh, command):
                    break

            # Set the tag 'Deployed' to 'True' on the instance
            self.inst_wrapper.add_tag(instance_id, "Deployed", "True")

            ssh.close()

        except paramiko.SSHException as e:
            print(f"SSH connection failed: {str(e)}")
        
        finally:
            ssh.close()

    def setup_gatekeeper(self, instance_id):
        """
        Set up the gatekeeper
        """
        console.print(f"\n**Setting the gatekeeper instance**", style="bold cyan")

        # Check if tag 'Deployed' is already set on the instance
        instance = self.inst_wrapper.ec2_client.describe_instances(
            InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]
        tags = instance.get("Tags")
        if tags:
            for tag in tags:
                if tag["Key"] == "Deployed" and tag["Value"] == "True":
                    console.print(
                        f"Setup already done for the gatekeeper instance."
                    )
                    return

        with open("./instance_startup_scripts/gatekeeper.txt", "r") as file:
            gatekeeper_commands = file.read()
        
        # Set the permission 400 to key_file_path
        os.chmod(self.key_wrapper.key_file_path, 0o400)
        os.chmod(os.path.dirname(self.key_wrapper.key_file_path), 0o700)

        public_ip = self.get_public_ip(instance_id)
        self.scp_dir_to_remote(self.key_wrapper.key_file_path, public_ip, "./logic", "~/")
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(
                hostname=public_ip, 
                username="ubuntu",
                key_filename=self.key_wrapper.key_file_path
            )

            # Get the trusted instance IP
            trusted_instance = self.inst_wrapper.exists("trusted")
            if trusted_instance:
                trusted_ip = trusted_instance["PrivateIpAddress"]

            gatekeeper_commands = gatekeeper_commands.replace("TRUSTED_IP_VAR", trusted_ip)
            gatekeeper_commands = gatekeeper_commands.split("\n")

            for command in gatekeeper_commands:
                if not self.execute_ssh_command_background_safe(ssh, command):
                    break

            # Set the tag 'Deployed' to 'True' on the instance
            self.inst_wrapper.add_tag(instance_id, "Deployed", "True")

            ssh.close()

        except paramiko.SSHException as e:
            print(f"SSH connection failed: {str(e)}")
        
        finally:
            ssh.close()

    def cleanup(self) -> None:
        """
        Cleans up all the resources created during the scenario, including disassociating
        and releasing the Elastic IP, terminating the instance, deleting the security
        group, and deleting the key pair.
        """
        console.print("\n********** Clean Up **********", style="bold cyan")

        with alive_bar(1, title="Cleaning up Instances") as bar:
            self.inst_wrapper.terminate()
            time.sleep(1)
            bar()
        
        console.print("\t- **Terminated Instances**")

        console.print(f"- **Cleaning Up Security Group**")
        if self.sg_wrapper.security_groups != []:
            with alive_bar(1, title="Deleting Security Group") as bar:
                self.sg_wrapper.delete_all()
                time.sleep(1)
                bar()

        console.print("\t- **Deleted Security Groups**")

        console.print(f"- **Key Pair**: {self.key_wrapper.key_pair['KeyName']}")
        if self.key_wrapper.key_pair:
            with alive_bar(1, title="Deleting Key Pair") as bar:
                self.key_wrapper.delete(self.key_wrapper.key_pair["KeyName"])
                time.sleep(0.4)
                bar()

        console.print("\t- **Deleted Key Pair**")

    def update_security_groups(self):

        proxy_instance = self.inst_wrapper.exists("proxy")
        if proxy_instance:
            proxy_ip = proxy_instance["PrivateIpAddress"]
        cluster_sg_permissions = [
            {
                "IpProtocol": "tcp",
                "FromPort": 3306,
                "ToPort": 3306,
                "IpRanges": [{"CidrIp": f"{proxy_ip}/32"}],
            },
            {
                "IpProtocol": "icmp",
                "FromPort": -1,
                "ToPort": -1,
                "IpRanges": [{"CidrIp": f"{proxy_ip}/32"}],
            }
        ]
        self.sg_wrapper.authorize_ingress("DbScenario-SG-cluster", ip_permissions=cluster_sg_permissions)

        """ for db_instance in DB_CLUSTER:
            # Add the security group to the instance
            instance_id = self.inst_wrapper.exists(db_instance["Name"])["InstanceId"]
            cluster_sg = self.sg_wrapper.exists("DbScenario-SG-cluster")
            self.sg_wrapper.add_security_group_to_instance(instance_id, cluster_sg) """

        trusted_instance = self.inst_wrapper.exists("trusted")
        if trusted_instance:
            trusted_ip = trusted_instance["PrivateIpAddress"]
        proxy_sg_permissions = [
            {
                "IpProtocol": "tcp",
                "FromPort": 8000,
                "ToPort": 8000,
                "IpRanges": [{"CidrIp": f"{trusted_ip}/32"}],
            }
        ]
        self.sg_wrapper.authorize_ingress("DbScenario-SG-proxy", ip_permissions=proxy_sg_permissions)
        """ for proxy_instance in PROXY:
            instance_id = self.inst_wrapper.exists(proxy_instance["Name"])["InstanceId"]
            proxy_sg = self.sg_wrapper.exists("DbScenario-SG-proxy")
            self.sg_wrapper.add_security_group_to_instance(instance_id, proxy_sg) """

        gatekeeper_instance = self.inst_wrapper.exists("gatekeeper")
        if gatekeeper_instance:
            gatekeeper_ip = gatekeeper_instance["PrivateIpAddress"]
        trusted_sg_permissions = [
            {
                "IpProtocol": "tcp",
                "FromPort": 8000,
                "ToPort": 8000,
                "IpRanges": [{"CidrIp": f"{gatekeeper_ip}/32"}],
            }
        ]
        self.sg_wrapper.authorize_ingress("DbScenario-SG-trusted", ip_permissions=trusted_sg_permissions)
        """ for trusted_instance in TRUSTED_HOST:
            instance_id = self.inst_wrapper.exists(trusted_instance["Name"])["InstanceId"]
            trusted_sg = self.sg_wrapper.exists("DbScenario-SG-trusted")
            self.sg_wrapper.add_security_group_to_instance(instance_id, trusted_sg) """

        gatekeeper_permissions = [
            {
                "IpProtocol": "tcp",
                "FromPort": 8000,
                "ToPort": 8000,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ]
        self.sg_wrapper.authorize_ingress("DbScenario-SG-gatekeeper", ip_permissions=gatekeeper_permissions)
        """gatekeeper_instance = self.inst_wrapper.exists("gatekeeper")
            if gatekeeper_instance:
            instance_id = gatekeeper_instance["InstanceId"]
            gatekeeper_sg = self.sg_wrapper.exists("DbScenario-SG-gatekeeper")
            self.sg_wrapper.add_security_group_to_instance(instance_id, gatekeeper_sg) """

    def run_benchmark(self):
        # Get the gatekeeper instance public ip
        gatekeeper_instance = self.inst_wrapper.exists("gatekeeper")
        if gatekeeper_instance:
            gatekeeper_ip = gatekeeper_instance["PublicIpAddress"]
        url = f"http://{gatekeeper_ip}:{8000}/query"

        execution_times = {}
        dispersion_of_reads_dict = {}
        methods = ["direct_hit", "random", "customized"]

        # Prepare headers for columns in the excel file
        with open("./benchmark_files/benchmark_results.xlsx", "w") as f:
            f.write("Implementation;Execution Time;Read Dispersion;Read Success Rate;Write Success Rate\n")

        for i in range(1, len(methods) + 1):
            dispersion_of_reads = {}
            read_passed = 0
            write_passed = 0
            start_time = time.time()

            console.print(f"Benchmarking READs for method: {methods[i-1]}")
            for _ in range(1000):
                query = "SELECT * FROM actor LIMIT 1;"
                payload = {"query": query, "implementation": i}

                response = None
                try:
                    response = requests.post(url, json=payload)
                    response.raise_for_status()
                    response = response.json()
                except requests.RequestException as e:
                    print(f"Request failed: {e}")
                    break

                if "error" not in response:
                    receiver = response["target_node"]
                    if receiver in dispersion_of_reads:
                        dispersion_of_reads[receiver] += 1
                    else:
                        dispersion_of_reads[receiver] = 1
                    read_passed += 1
                else:
                    print(f"Read error: {response['error']}")
                    break

            console.print(f"Benchmarking WRITEs for method: {methods[i-1]}")
            for _ in range(1000):

                query = "INSERT INTO actor (first_name, last_name) VALUES ('marco', 'mud');"
                payload = {"query": query, "implementation": i}

                response = None
                try:
                    response = requests.post(url, json=payload)
                    response.raise_for_status()
                    response = response.json()
                except requests.RequestException as e:
                    print(f"Request failed: {e}")
                    break
                
                if "error" not in response:
                    write_passed += 1
                else:
                    print(f"Write error: {response['error']}")
                    break
            
            read_success_rate = read_passed / 1000
            write_success_rate = write_passed / 1000
            execution_times[i] = time.time() - start_time
            dispersion_of_reads_dict[i] = dispersion_of_reads
            console.print(f"Read success rate for method {methods[i-1]}: {read_success_rate}")
            console.print(f"Write success rate for method {methods[i-1]}: {write_success_rate}")
            console.print(f"Execution time for method {methods[i-1]}: {execution_times[i]}")
            console.print(f"Dispersion of reads for method {methods[i-1]}: {dispersion_of_reads}")

            with open("./benchmark_files/benchmark_results.xlsx", "a") as f:
                f.write(f"{methods[i-1]};{execution_times[i]};{dispersion_of_reads};{read_success_rate};{write_success_rate}\n")
    
    def run_scenario(self) -> None:
        """
        Executes the entire EC2 instance scenario: creates key pairs, security groups,
        launches an instance and cleans up all resources.
        """
        logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

        console.print("-" * 88)
        console.print(
            "Welcome to this Amazon Elastic Compute Cloud (Amazon EC2) demo.",
            style="bold magenta",
        )
        console.print("-" * 88)
        
        console.print("\n**Initializing: Create Security Group {name}**", style="bold cyan")
        self.create_security_groups()

        console.print("\n**Initializing: Create Key Pair**", style="bold cyan")
        self.create_and_list_key_pairs()

        console.print("\n**Create DB Cluster instances**", style="bold cyan")
        for db_instance in DB_CLUSTER:
            # Check if the instance already exists
            if not self.retrieve_instance(db_instance["Name"]):
                console.print(f"Creating instance {db_instance['Name']}...")
                self.create_named_instance(db_instance["Name"], DB_INSTANCES_AMI, db_instance["Type"], "DbScenario-SG-cluster")
            else:
                console.print(f"Instance {db_instance['Name']} already exists.")

            # Get the instance named db_instance["Name"]
            instance = self.inst_wrapper.exists(db_instance["Name"])
            if instance:
                self.setup_mysql(instance["InstanceId"], db_instance["Name"])
            else:
                console.print(f"Failed to install MySQL on instance {db_instance['Name']}")

        console.print("\n**Create proxy instance**", style="bold cyan")
        for proxy_instance in PROXY:
            # Check if the instance already exists
            if not self.retrieve_instance(proxy_instance["Name"]):
                console.print(f"Creating instance {proxy_instance['Name']}...")
                self.create_named_instance(proxy_instance["Name"], PROXY_INSTANCE_AMI, proxy_instance["Type"], "DbScenario-SG-proxy")
            else:
                console.print(f"Instance {proxy_instance['Name']} already exists.")

            # Get the instance named proxy_instance["Name"]
            instance = self.inst_wrapper.exists(proxy_instance["Name"])
            if instance:
                self.setup_proxy(instance["InstanceId"])
            else:
                console.print(f"Failed to setup instance {proxy_instance['Name']}")

        console.print("\n**Create trusted host instance**", style="bold cyan")
        for trusted_instance in TRUSTED_HOST:
            # Check if the instance already exists
            if not self.retrieve_instance(trusted_instance["Name"]):
                console.print(f"Creating instance {trusted_instance['Name']}...")
                self.create_named_instance(trusted_instance["Name"], TRUSTED_HOSTS_INSTANCES_AMI, trusted_instance["Type"], "DbScenario-SG-trusted")
            else:
                console.print(f"Instance {trusted_instance['Name']} already exists.")

            instance = self.inst_wrapper.exists(trusted_instance["Name"])
            if instance:
                self.setup_trusted_host(instance["InstanceId"])
            else:
                console.print(f"Failed to setup instance {trusted_instance['Name']}")


        console.print("\n**Create gatekeeper instance**", style="bold cyan")
        for gatekeeper_instance in GATEKEEPER:
            # Check if the instance already exists
            if not self.retrieve_instance(gatekeeper_instance["Name"]):
                console.print(f"Creating instance {gatekeeper_instance['Name']}...")
                self.create_named_instance(gatekeeper_instance["Name"], GATEKEEPER_INSTANCES_AMI, gatekeeper_instance["Type"], "DbScenario-SG-gatekeeper")
            else:
                console.print(f"Instance {gatekeeper_instance['Name']} already exists.")

            # Get the instance named gatekeeper_instance["Name"]
            instance = self.inst_wrapper.exists(gatekeeper_instance["Name"])
            if instance:
                self.setup_gatekeeper(instance["InstanceId"])
            else:
                console.print(f"Failed to setup instance {gatekeeper_instance['Name']}")

        console.print("\n**Updating security groups**", style="bold cyan")
        self.update_security_groups()

        console.print("\n**Running benchmark**", style="bold cyan")
        self.run_benchmark()

        console.print("\nThanks for watching!", style="bold green")
        console.print("-" * 88)

if __name__ == "__main__":
    scenario = DbClusterScenario(
        EC2InstanceWrapper.from_client(),
        KeyPairWrapper.from_client(),
        SecurityGroupWrapper.from_client(),
        remote_exec=False
    )
    try:
        scenario.run_scenario()
        input("Press Enter to exit...")
        scenario.cleanup()

    except Exception:
        logging.exception("Something went wrong with the demo.")
        scenario.cleanup()