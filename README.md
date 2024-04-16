
# IP-auth


> **This repository contains an early prototype, and is not meant to be used in the production use case. Feel free to try it out, leave feedback, and report issues.**

## Status

[![REUSE status](https://api.reuse.software/badge/github.com/kyma-project/ip-auth)](https://api.reuse.software/info/github.com/kyma-project/ip-auth)

## Overview
<!--- mandatory section --->

IP-auth is an external authorizer for Istio Ingress Gateway. It is a simple service that checks if the request's IP address is not in a list of blocked IP ranges. If the IP address is not in the list, the service returns a 200 OK response. If the IP address is in the list, the service returns a 403 Forbidden response.

![](./ip-auth.drawio.svg)

The list of blocked IP ranges can be stored in a file. The service reads the file on startup. There is also possibility to fetch the list from a remote server by providing the config file with the connection details. 


## Prerequisites

- kubectl
- kubernetes cluster with Kyma istio module installed

## Installation

Enable ip-auth in the istio module by adding the following configuration to the `istio` CR:

```yaml
spec:
  config:
    authorizers:
    - name: ip-auth
      port: 8000
      service: ip-auth.ip-auth.svc.cluster.local
      headers:
        inCheck:
          include:
          - x-envoy-external-address
          - x-forwarded-for      
```

You can edit the `istio` CR by running the following command:
```bash
kubectl edit istio -n kyma-system default
```

If you run your cluster on Google Cloud Platform or Microsoft Azure, you need to enable externalTrafficPolicy: Local in the istio-ingressgateway service. You can do this by running the following command:
```bash
kubectl patch svc istio-ingressgateway -n istio-system -p '{"spec":{"externalTrafficPolicy":"Local"}}'
```

Now create `ip-auth` namespace where the service with the configuration will be deployed.
  
```bash 
kubectl create namespace ip-auth
```

The content of the config file should look like this:
```yaml
clientId: here-goes-your-client-id
clientSecret: here-goes-your-client-secret
tokenUrl: https://example.com/oauth2/token
policyUrl: https://example.com/policy
usePolicyFile: true
usePolicyUrl: false
policyUpdateInterval: 600
```

To create a config secret run the following command:
```bash 
kubectl -n ip-auth create secret generic config --from-file=config.yaml=sample-config.yaml
```

If you want to use a static list of blocked IP ranges, you can create the config file with the list of blocked IP ranges and create the config map from it. The content of the `policy.json` file should look like this:

```json
[
  {
    "network": "1.2.3.0/24",
    "policy": "BLOCK_ACCESS"
  },
  {
    "network": "2.4.0.0/16",
    "policy": "BLOCK_ACCESS"
  },
  {
    "network": "5.6.7.128/25",
    "policy": "BLOCK_ACCESS"
  }
]
```

You can create the config map from the file by running the following command:
```bash
kubectl -n ip-auth create configmap policy --from-file=policy.json
```

To install ip-auth apply [ip-auth.yaml](ip-auth.yaml) manifest in your cluster:
```bash
kubectl apply -f https://raw.githubusercontent.com/kyma-project/ip-auth/main/ip-auth.yaml
```

It also creates AuthorizationPolicy that enables custom authorizer for all requests coming to istio ingress gateway.

## Testing with your own IP

Deploy sample workload to test the service. You can use the following command:
```bash
kubectl apply -f https://raw.githubusercontent.com/kyma-project/ip-auth/main/workload.yaml
```
The sample workload URL can be fetched from this command:
```bash
export WORKLOAD_URL=$(kubectl get virtualservice -l apirule.gateway.kyma-project.io/v1beta1=httpbin.workload -n workload -ojsonpath='{.items[0].spec.hosts[0]}')
```
Now you can test the service:
```bash
curl -i "https://$WORKLOAD_URL/headers"
```
You should get a 200 OK response with the headers like this::
```
{
  "headers": {
    "Accept": "*/*", 
    "Host": "httpbin.xxxxx.kyma.ondemand.com", 
    "User-Agent": "curl/8.4.0", 
    "X-Envoy-Attempt-Count": "1", 
    "X-Envoy-External-Address": "121.122.123.124", 
    "X-Forwarded-Host": "httpbin.xxxx.kyma.ondemand.com"
  }
}
```
Now take the IP address from the `X-Envoy-External-Address` header and add it to the `policy.json` file. And recreate the config map with the new policy:
```bash
kubectl -n ip-auth create configmap policy --from-file=policy.json --dry-run=client -o yaml | kubectl apply -f -
```
Now restart the ip-auth service:
```bash
kubectl rollout restart deployment -n ip-auth ip-auth
```
Now when you run the curl command again, you should get a 403 Forbidden response.

## Local development and testing

You can start ip-auth locally by running the following command:
```bash
go run main.go
```

Without config file, the service will use policy.json file from current directory. You can test the service by sending a request with the `x-envoy-external-address` header set to the IP address you want to check. For example:

```bash
curl -v -H "x-envoy-external-address: 1.2.3.0" 
```

If the IP address is in the list of blocked IP ranges, the service will return a 403 Forbidden response. If the IP address is not in the list, the service will return a 200 OK response.


## Links

More information about istio module in Kyma can be found [here](https://kyma-project.io/docs/components/istio).

## Contributing
<!--- mandatory section - do not change this! --->

See the [Contributing Rules](CONTRIBUTING.md).

## Code of Conduct
<!--- mandatory section - do not change this! --->

See the [Code of Conduct](CODE_OF_CONDUCT.md) document.

## Licensing
<!--- mandatory section - do not change this! --->

See the [license](./LICENSE) file.
