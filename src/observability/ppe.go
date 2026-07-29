package observability

const (
	MetricPPESupported              = "b4_ppe_supported"
	MetricPPERulesPresent           = "b4_ppe_rules_present"
	MetricPPERuleReapply            = "b4_ppe_rule_reapply_total"
	MetricPPESelfTest               = "b4_ppe_self_test_total"
	MetricPPESelfTestDuration       = "b4_ppe_self_test_duration_ms"
	MetricCaptureOutgoingVisibility = "b4_capture_outgoing_visibility"
	MetricCaptureIncomingVisibility = "b4_capture_incoming_visibility"
	MetricCaptureVisibilityDegrade  = "b4_capture_visibility_degrade_total"
	MetricHoldDisabledVisibility    = "b4_hold_disabled_visibility_total"
)
