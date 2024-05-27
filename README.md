# mackerel-plugin-libreswan

## Description

Mackerel metrics plugin to get informations of Libreswan VPN software.

## Synopsis

```sh
mackerel-plugin-libreswan [-docker-exec=<container-name>] [-tempfile=<temp-file-path>]
```

## Installation

```sh
sudo mkr plugin install Arthur1/mackerel-plugin-libreswan
```

## Setting for mackerel-agent

```toml

[plugin.metrics.palworld]
command = ["/opt/mackerel-agent/plugins/bin/mackerel-plugin-libreswan", "-password", "admin_password"]
```

## Usage

### Options

```
  -docker-exec string
    	docker container name which contains ipsec command
  -tempfile string
    	temp file name
```
