# Event DRIven Network Telemetry

`edrint` is a tool to extract different types of metadata from network packets. 
The tool (written in Golang) is designed to be general and 
extensible to support various network data processing requirements such as
timeseries counters (i/o graph in wireshark), passive TCP measurements, byte pattern extraction etc.

The source of data is network packets which can be in a `pcap` or captured live from network interface. 

There are 3 core components in this event driven architecture:
* A simple event bus (using topics and event handlers)
* Processor (can subscribe and publish different events)
* Telemetry Functions (Functions that operate within a `flow context` by receiving packets of a particular bidirectional flow)

A few `Processor`s that come with the tool by default are:
* PacketParser (produces events of type `packet`)
* Flow (consumes `packet`s and creates `flow` state (identified by 5-tuple))
* Classifier (associates a `class` to a `flow`)
* TelemetryManager (attaches `Telemetry Functions` to `flow`s based on it's `class`)
* Dumper (creates JSON dumps of any event)