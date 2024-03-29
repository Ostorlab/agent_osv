<h1 align="center">Agent OSV</h1>

<p align="center">
<img src="https://img.shields.io/badge/License-Apache_2.0-brightgreen.svg">
<img src="https://img.shields.io/github/languages/top/ostorlab/agent_osv">
<img src="https://img.shields.io/github/stars/ostorlab/agent_osv">
<img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg">
</p>

_OSV Scanner is an open-source vulnerability scanner, used to identify security vulnerabilities in software dependencies._

---


This repository is an implementation of [Ostorlab Agent](https://pypi.org/project/ostorlab/) for the [OSV Scanner](https://github.com/google/osv-scanner) by Google.

## Getting Started
To perform your first scan, simply run the following command:
```shell
oxo scan run --install --agent agent/ostorlab/osv file
```

This command will download and install `agent/ostorlab/osv` and target the file.
For more information, please refer to the [OXO Documentation](https://oxo.ostorlab.co/docs)


## Usage

Agent OSV can be installed directly from the oxo agent store or built from this repository.

 ### Install directly from oxo agent store

 ```shell
 oxo agent install agent/ostorlab/osv
 ```

You can then run the agent with the following command:
```shell
oxo scan run --agent agent/ostorlab/osv file
```


### Build directly from the repository

 1. To build the OSV agent you need to have [oxo](https://pypi.org/project/ostorlab/) installed in your machine.  if you have already installed oxo, you can skip this step.

```shell
pip3 install ostorlab
```

 2. Clone this repository.

```shell
git clone https://github.com/Ostorlab/agent_osv.git && cd agent_osv
```

 3. Build the agent image using oxo cli.

 ```shell
 oxo agent build --file=ostorlab.yaml
 ```

 You can pass the optional flag `--organization` to specify your organisation. The organization is empty by default.

 4. Run the agent using on of the following commands:
	 * If you did not specify an organization when building the image:
    ```shell
    oxo scan run --agent agent//osv file
    ```
	 * If you specified an organization when building the image:
    ```shell
    oxo scan run --agent agent/[ORGANIZATION]/osv file
    ```


## License
[Apache](./LICENSE)
