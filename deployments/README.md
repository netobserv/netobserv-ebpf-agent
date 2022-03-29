# Deployment example files

This directory contains some example files that show how the netobserv-agent
can be deployed. In production, the agent is deployed by the Network Observability Operator
but the files contained here are useful for documentation and manual testing.

* `flp-daemonset.yml`, shows how to deploy/configure the Agent when Flowlogs Pipeline is deployed
  as daemonset, taking the target host configuration from the Host IP.
* `flp-service.yml`, shows how to deploy/configure the Agent when Flowlogs Pipeline is deployed
  as a service, explicitly setting the host configuration as the service name.