<h1 align="center">Agent OSV</h1>

<p align="center">
<img src="https://img.shields.io/badge/License-Apache_2.0-brightgreen.svg">
<img src="https://img.shields.io/github/languages/top/ostorlab/agent_osv">
<img src="https://img.shields.io/github/stars/ostorlab/agent_osv">
<img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg">
</p>

_OSV Scanner is an open-source vulnerability scanner, used to identify security vulnerabilities in software dependencies._

---

<p align="center">
<img src="https://github.com/Ostorlab/agent_osv/blob/main/images/logo.png" alt="agent-osv" />
</p>

This repository is an implementation of [Ostorlab Agent](https://pypi.org/project/ostorlab/) for the [OSV Scanner](https://github.com/google/osv-scanner) by Google.

## Getting Started
To perform your first scan, simply run the following command:
```shell
ostorlab scan run --install --agent agent/ostorlab/osv file lockfile.txt
```

This command will download and install `agent/ostorlab/osv` and target the file `lockfile.txt`.
For more information, please refer to the [Ostorlab Documentation](https://github.com/Ostorlab/ostorlab/blob/main/README.md)


## Usage

Agent OSV can be installed directly from the ostorlab agent store or built from this repository.

 ### Install directly from ostorlab agent store

 ```shell
 ostorlab agent install agent/ostorlab/osv
 ```

You can then run the agent with the following command:
```shell
ostorlab scan run --agent agent/ostorlab/osv file lockfile.txt
```


### Build directly from the repository

 1. To build the OSV agent you need to have [ostorlab](https://pypi.org/project/ostorlab/) installed in your machine.  if you have already installed ostorlab, you can skip this step.

```shell
pip3 install ostorlab
```

 2. Clone this repository.

```shell
git clone https://github.com/Ostorlab/agent_osv.git && cd agent_osv
```

 3. Build the agent image using ostorlab cli.

 ```shell
 ostortlab agent build --file=ostorlab.yaml
 ```

 You can pass the optional flag `--organization` to specify your organisation. The organization is empty by default.

 4. Run the agent using on of the following commands:
	 * If you did not specify an organization when building the image:
    ```shell
    ostorlab scan run --agent agent//osv file lockfile.txt
    ```
	 * If you specified an organization when building the image:
    ```shell
    ostorlab scan run --agent agent/[ORGANIZATION]/osv file lockfile.txt
    ```


## License
[Apache](./LICENSE)
