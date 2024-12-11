# AWS MySQL Cluster Cloud Designing

This repository implements a scalable and secure MySQL cluster on AWS, leveraging the **Proxy** and **Gatekeeper** design patterns.

---

## Features

- **MySQL Cluster**: 
  - Master and two worker nodes deployed on AWS EC2.
- **Proxy Pattern**:
  - **Direct Hit**: All requests sent to the master.
  - **Random**: Read requests distributed randomly across workers.
  - **Customized**: Reads routed to the worker with the least latency.
- **Gatekeeper Pattern**:
  - Secures access using a gatekeeper and trusted host.
- **Benchmarking**:
  - Evaluates performance for 1000 read and write requests per implementation.

---

## Setup

### Clone the Repository
```bash
git clone https://github.com/marcomudenge/AWS_MySQL_Cluster_Cloud_Designing.git
cd AWS_MySQL_Cluster_Cloud_Designing
```
### Install requirements and run the experiment
```PS
./run_all.ps1
```
