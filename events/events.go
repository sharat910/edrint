package events

const (
	PACKET         = Topic("packet")
	CLASSIFICATION = Topic("classification")

	FLOW_CREATED          = Topic("flow.created")
	FLOW_EXPIRED          = Topic("flow.expired")
	FLOW_ATTACH_TELEMETRY = Topic("flow.attach_telemetry")

	PROTOCOL_SNI = Topic("protocol.sni")
	PROTOCOL_DNS = Topic("protocol.dns")

	TELEMETRY_FLOWSUMMARY    = Topic("telemetry.flowsummary")
	TELEMETRY_FLOWPRINT      = Topic("telemetry.flowprint")
	TELEMETRY_FLOWPULSE      = Topic("telemetry.flowpulse")
	TELEMETRY_TCP_RTT        = Topic("telemetry.tcp.rtt")
	TELEMETRY_TCP_RETRANSMIT = Topic("telemetry.tcp.retransmit")
	TELEMETRY_GAP_CHUNK      = Topic("telemetry.gap_chunk")
	TELEMETRY_FRAME          = Topic("telemetry.frame")
	TELEMETRY_HTTP_CHUNK     = Topic("telemetry.http_chunk")
	TELEMETRY_HTTP_REQ       = Topic("telemetry.http_req")
	TELEMETRY_FLOWLET        = Topic("telemetry.flowlet")
)
