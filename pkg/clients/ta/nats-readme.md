# HVS Subscriber Client

## Scope

Addresses...
* Network constraints that limit the Trust-Agent's ability to open/listen a port (i.e., for the go webserver).

Does not address...
* Attestation at reboot
* 24 hour Trust-Status-Latency of v3.x

*Basically, it's v3.x behavior without the Trust-Agent opening/listening on a port.*

&nbsp;
## Implementation

See...
* Trust-Agent changes: https://github.com/kwtj43/go-trustagent/tree/feature/hvs_subscriber
* HVS changes: https://github.com/kwtj43/intel-secl/tree/feature/hvs_subscriber


```
┌──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                                                                                                              │
│                  ┌───────────────────────────────────────────────────────────────────────────────────────────────────────┐   │
│                  │                             I S E C L   C O N T R O L   P L A N E                                     │   │
│                  │                                                                                                       │   │
│                  │                                                                                                       │   │
│                  │                                 ┌─────────────────────────────────────────────────────────────┐       │   │
│                  │                                 │                         H  V  S                             │       │   │
│                  │                                 │                                                             │       │   │
│                  │                                 │     ┌───────┐     ┌──────────────┐  ┌──────────────────┐    │       │   │
│                  │                                 │     │  fvs  │     │  lib/flavor  │  │ report-controller│    │       │   │
│                  │                                 │     └───┬───┘     └────────┬─────┘  └────────┬─────────┘    │       │   │
│                  │                                 │         │                  │                 │              │       │   │
│                  │                                 │         │                  │                 │              │       │   │
│                  │                                 │         │                  │                 │              │       │   │
│                  │                                 │         │                  │                 │              │       │   │
│                  │                                 │         └──────────────────┼─────────────────┘              │       │   │
│   ┌─────┐        │                                 │                            │                                │       │   │
│   │ ta1 ├────┐   │                                 │                            │                                │       │   │
│   └─────┘    │   │                                 │                 ┌──────────▼─────────────┐                  │       │   │
│              │   │   ┌─────────────────┐           │                 │  intel-host-connector  │                  │       │   │
|           ┌──┼───┼──►│  nats-server-1  │◄────┐     │                 └─┬───────────────────┬──┘                  │       │   │
│   ┌─────┐ │  │   │   └─────────────────┘     │     │                   │                   │                     │       │   │
│   │ ta2 ├─┘  │   │                           │     │                   │                   │                     │       │   │   
│   └─────┘    │   │                           │     │                   │                   │                     │       │   │
│              │   │   ┌─────────────────┐     │     │      intel:nats://{hardware-id}   intel:http://...          │       │   │
│   ┌─────┐    │───┼──►│  nats-server-2  │◄────┤     │                   │                   │                     │       │   │
│   │ ta3 ├────┘   │   └─────────────────┘     │     │        ┌──────────▼─────┐     ┌───────▼──────────────┐      │       │   │
│   └─────┘        │                           ├─────┼────────┤  NATs TAClient │     │  Existing "TAClient" │      │       │   │
│                  │   ┌─────────────────┐     │     │        └────────────────┘     └──────────────────────┘      │       │   │
│   ┌─────┐   ┌────┼──►│  nats-server-3  │◄────┘     │                                                             │       │   │
│   │ ta4 ├───┘    │   └─────────────────┘           │                                                             │       │   │
│   └─────┘        │                                 │                                                             │       │   │
│                  │                                 └─────────────────────────────────────────────────────────────┘       │   │
│                  │                                                                                                       │   │
│                  └───────────────────────────────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                                                              │
└──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### Demo
1) Start nats-server: `docker run -d --rm -p 4222:4222 -p 8222:8222 nats:latest`
1) Configure HVS to communicate with nats-server (/etc/hvs/config.yml)
2) hvs erase-data
3) Configure Trust-Agent to communicat with nats-server
4) Start Trust-Agent: `./tagent push` and get hardware-uuid
5) Confirm that Trust-Agent is not listening on network ports (`netstat -lntp` does not include `tagent`)
5) Use Postman to register nats-ta, import flavors and create reports.

## Functional Impact

### HVS Deployment
* Deploy one or more nats-servers in the control plane (currently using `docker run -d --rm -p 4222:4222 -p 8222:8222 nats:latest`)
* Add the list of nats-servers to `/etc/hvs/config.yaml`...
    ```
    vcss:
      refresh-period: 2m0s
    nats:
      servers: [
        "nats://10.105.167.153:4222",
        "nats://<TBD>:4222"
      ]
    ```

### Trust-Agent Deployment
* Update /opt/trustagent/configuration/config.yaml to point the Trust-Agent to the nats-server...
    ```
    nats:
      url: "nats://10.105.167.153:4222"
    ```
* Start the Trust-Agent using nats: `./tagent push`

### Remaining Work
* TLS between TA and nats-server
* Authentication between TA and nats-server/hvs
* TLS between HVS and nats-server
* Authentication between HVS and nast-server
* Implement remaining request/reply use cases (ex. deploy asset tag, manifest, etc.)
* Refactor trustagent code (to share common code used by webserver/nats client)
* Add reconnect logic to nats client (TA and HVS)
* Support for multiple nats-servers
* Close on connection strings (intel:nats://{hardwareuuid}?, hostname?, other?)
* TA setup for nats and config changes.