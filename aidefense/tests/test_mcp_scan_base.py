import pytest
from unittest.mock import MagicMock

from aidefense.config import Config
from aidefense.exceptions import ApiError
from aidefense.mcpscan.mcp_scan_base import MCPScan
from aidefense.mcpscan.models import (
	AuthConfig,
	AuthType,
	CapabilityType,
	FilterOptions,
	GetMCPServerScanReportRequest,
	GetMCPServerScanReportResponse,
	GetMCPServerScanResultsResponse,
	ThreatSeverityLevel,
	TransportType,
	ValidateMCPServersRequest,
	ValidateMCPServersResponse,
)


TEST_API_KEY = "0123456789" * 6 + "0123"


@pytest.fixture(autouse=True)
def reset_config_singleton():
	"""Reset Config singleton before each test."""
	Config._instance = None
	yield
	Config._instance = None


@pytest.fixture
def mock_request_handler():
	"""Create a mock request handler."""
	return MagicMock()


@pytest.fixture
def mcp_scan(mock_request_handler):
	"""Create an MCPScan instance with a mocked request layer."""
	client = MCPScan(api_key=TEST_API_KEY, request_handler=mock_request_handler)
	client.make_request = MagicMock()
	return client


class TestMCPScan:
	"""Tests for MCPScan base methods."""

	def test_get_server_scan_results(self, mcp_scan):
		"""Test retrieving detailed scan results for a registered server."""
		server_id = "550e8400-e29b-41d4-a716-446655440000"
		mock_response = {
			"serverId": server_id,
			"completedAt": "2026-01-01T00:00:00Z",
			"isSafe": False,
			"rawResult": "scan-output",
			"capabilities": {
				"toolResults": {
					"cap-123": {
						"items": [
							{
								"capabilityId": "cap-123",
								"capabilityName": "dangerous_tool",
								"capabilityDescription": "Tool capable of executing remote actions",
								"capabilityType": "TOOL",
								"status": "SCAN_COMPLETED",
								"isSafe": False,
								"analyzerType": "LLM",
								"severity": "HIGH",
								"threatNames": ["Prompt Injection", "Privilege Abuse"],
								"threatSummary": "Multiple high-risk patterns detected",
								"totalFindings": 2,
								"techniqueId": "AITech-1",
								"techniqueName": "Prompt Injection",
								"threats": [
									{
										"subTechniqueId": "AISubtech-1.1",
										"subTechniqueName": "Tool Manipulation",
										"severity": "HIGH",
										"description": "The tool can be redirected by crafted input",
										"indicators": ["shell_exec", "external_call"],
										"standard_mappings": ["OWASP LLM01"],
									}
								],
							}
						]
					}
				}
			},
		}
		mcp_scan.make_request.return_value = mock_response

		response = mcp_scan.get_server_scan_results(server_id)

		mcp_scan.make_request.assert_called_once_with(
			method="GET",
			path=f"mcp/servers/{server_id}/scan",
		)
		assert isinstance(response, GetMCPServerScanResultsResponse)
		assert response.server_id == server_id
		assert response.is_safe is False
		assert response.raw_result == "scan-output"
		assert response.capabilities is not None
		assert "cap-123" in response.capabilities.tool_results
		result_item = response.capabilities.tool_results["cap-123"].items[0]
		assert result_item.capability_id == "cap-123"
		assert result_item.capability_name == "dangerous_tool"
		assert result_item.capability_description == "Tool capable of executing remote actions"
		assert result_item.threat_names == ["Prompt Injection", "Privilege Abuse"]
		assert result_item.threat_summary == "Multiple high-risk patterns detected"
		assert result_item.total_findings == 2
		assert result_item.threats[0].description == "The tool can be redirected by crafted input"
		assert result_item.threats[0].indicators == ["shell_exec", "external_call"]
		assert result_item.threats[0].standard_mappings == ["OWASP LLM01"]

	def test_trigger_server_scan(self, mcp_scan):
		"""Test triggering an on-demand server scan."""
		server_id = "550e8400-e29b-41d4-a716-446655440001"
		mcp_scan.make_request.return_value = {}

		result = mcp_scan.trigger_server_scan(server_id)

		mcp_scan.make_request.assert_called_once_with(
			method="POST",
			path=f"mcp/servers/{server_id}/scan",
			data={},
		)
		assert result is None

	def test_server_scan_report(self, mcp_scan):
		"""Test retrieving a filtered scan report for a registered server."""
		request = GetMCPServerScanReportRequest(
			server_id="550e8400-e29b-41d4-a716-446655440002",
			offset=10,
			filter_options=FilterOptions(
				capability_type=CapabilityType.TOOL,
				threat_severity=[ThreatSeverityLevel.HIGH, ThreatSeverityLevel.CRITICAL],
			),
		)
		mock_response = {
			"reports": {
				"items": [
					{
						"capability": {
							"capabilityType": "TOOL",
							"tool": {
								"id": "tool-123",
								"name": "run_shell",
								"description": "Execute shell commands",
								"title": "Run Shell",
								"input_schema": {
									"arguments": [
										{
											"name": "command",
											"description": "Command to execute",
											"type": "string",
											"required": True,
										}
									]
								},
								"output_schema": {
									"arguments": [
										{
											"name": "stdout",
											"description": "Command output",
											"type": "string",
										}
									]
								},
								"annotations": {"risk": "critical"},
							},
						},
						"threats": [
							{
								"techniqueId": "AITech-2",
								"techniqueName": "Command Execution",
								"analyzerType": "YARA",
								"completedAt": "2026-01-01T00:03:00Z",
								"sourceFile": "tools/run_shell.py",
								"description": "The tool exposes unrestricted shell access",
								"subTechniques": [
									{
										"subTechniqueId": "AISubtech-2.4",
										"subTechniqueName": "Arbitrary Command Execution",
										"severity": "CRITICAL",
									}
								],
							}
						],
					}
				]
			},
			"paging": {"total": 1, "limit": 25, "offset": 10},
		}
		mcp_scan.make_request.return_value = mock_response

		response = mcp_scan.server_scan_report(request)

		mcp_scan.make_request.assert_called_once_with(
			method="POST",
			path="mcp/servers/550e8400-e29b-41d4-a716-446655440002/scan/report",
			data=request.to_body_dict(),
		)
		assert isinstance(response, GetMCPServerScanReportResponse)
		assert response.reports is not None
		assert response.reports.items is not None
		assert len(response.reports.items) == 1
		assert response.reports.items[0].capability is not None
		assert response.reports.items[0].capability.tool is not None
		tool = response.reports.items[0].capability.tool
		assert tool.name == "run_shell"
		assert tool.title == "Run Shell"
		assert tool.annotations == {"risk": "critical"}
		assert tool.input_schema is not None
		assert tool.input_schema.arguments[0].name == "command"
		assert tool.output_schema is not None
		assert tool.output_schema.arguments[0].name == "stdout"
		assert response.reports.items[0].threats is not None
		assert response.reports.items[0].threats[0].source_file == "tools/run_shell.py"
		assert response.reports.items[0].threats[0].description == "The tool exposes unrestricted shell access"
		assert response.reports.items[0].threats[0].sub_techniques[0].sub_technique_name == "Arbitrary Command Execution"
		assert response.paging is not None
		assert response.paging.total == 1
		assert response.paging.offset == 10

	@pytest.mark.parametrize(
		("capability_type", "capability_payload", "expected_field", "expected_value"),
		[
			(
				CapabilityType.PROMPT,
				{
					"capabilityType": "PROMPT",
					"prompt": {
						"id": "prompt-123",
						"name": "summarize_email",
						"description": "Summarizes inbound email content",
						"title": "Summarize Email",
						"input_schema": [
							{
								"name": "email_body",
								"description": "Raw email body",
								"required": True,
							}
						],
					},
				},
				"prompt",
				"summarize_email",
			),
			(
				CapabilityType.RESOURCE,
				{
					"capabilityType": "RESOURCE",
					"resource": {
						"id": "resource-123",
						"name": "server_config",
						"description": "Server configuration document",
						"title": "Server Config",
						"uri": "file:///configs/server.yaml",
						"mime_type": "application/yaml",
					},
				},
				"resource",
				"server_config",
			),
		],
	)
	def test_server_scan_report_non_tool_capabilities(
		self,
		mcp_scan,
		capability_type,
		capability_payload,
		expected_field,
		expected_value,
	):
		"""Test scan report parsing for prompt and resource capability variants."""
		request = GetMCPServerScanReportRequest(
			server_id="550e8400-e29b-41d4-a716-446655440004",
			offset=0,
			filter_options=FilterOptions(
				capability_type=capability_type,
				threat_severity=[ThreatSeverityLevel.MEDIUM],
			),
		)
		mock_response = {
			"reports": {
				"items": [
					{
						"capability": capability_payload,
						"threats": [
							{
								"techniqueId": "AITech-3",
								"techniqueName": "Data Exposure",
								"analyzerType": "API",
								"subTechniques": [
									{
										"subTechniqueId": "AISubtech-3.1",
										"subTechniqueName": "Sensitive Data Disclosure",
										"severity": "MEDIUM",
									}
								],
							}
						],
					}
				]
			},
			"paging": {"total": 1, "limit": 25, "offset": 0},
		}
		mcp_scan.make_request.return_value = mock_response

		response = mcp_scan.server_scan_report(request)

		mcp_scan.make_request.assert_called_once_with(
			method="POST",
			path="mcp/servers/550e8400-e29b-41d4-a716-446655440004/scan/report",
			data=request.to_body_dict(),
		)
		assert response.reports is not None
		assert response.reports.items is not None
		capability = response.reports.items[0].capability
		assert capability is not None
		selected_capability = getattr(capability, expected_field)
		assert selected_capability is not None
		assert selected_capability.name == expected_value
		assert response.reports.items[0].threats is not None
		assert response.reports.items[0].threats[0].sub_techniques[0].sub_technique_name == "Sensitive Data Disclosure"

	def test_validate_servers(self, mcp_scan):
		"""Test validating a batch of MCP server URLs."""
		request = ValidateMCPServersRequest(
			urls=[
				"https://valid.example.com/sse",
				"https://invalid.example.com/sse",
			],
			transport_type=TransportType.SSE,
			auth_config=AuthConfig(auth_type=AuthType.NO_AUTH),
		)
		mock_response = {
			"validUrls": ["https://valid.example.com/sse"],
			"invalidUrls": [
				{
					"url": "https://invalid.example.com/sse",
					"errorInfo": {
						"message": "Connection failed",
						"error_message": "dial tcp timeout",
						"remediation_tips": ["Verify the endpoint is reachable"],
						"occurred_at": "2026-01-01T00:05:00Z",
					},
				}
			],
		}
		mcp_scan.make_request.return_value = mock_response

		response = mcp_scan.validate_servers(request)

		mcp_scan.make_request.assert_called_once_with(
			method="POST",
			path="mcp/servers:validate",
			data=request.to_body_dict(),
		)
		assert isinstance(response, ValidateMCPServersResponse)
		assert response.valid_urls == ["https://valid.example.com/sse"]
		assert len(response.invalid_urls) == 1
		assert response.invalid_urls[0].url == "https://invalid.example.com/sse"
		assert response.invalid_urls[0].error_info.message == "Connection failed"
		assert response.invalid_urls[0].error_info.error_message == "dial tcp timeout"
		assert response.invalid_urls[0].error_info.remediation_tips == ["Verify the endpoint is reachable"]
		assert response.invalid_urls[0].error_info.occurred_at is not None

	def test_server_scan_methods_propagate_api_errors(self, mcp_scan):
		"""Test new MCPScan methods propagate API errors unchanged."""
		mcp_scan.make_request.side_effect = ApiError("API Error", 500)

		with pytest.raises(ApiError, match="API Error"):
			mcp_scan.get_server_scan_results("550e8400-e29b-41d4-a716-446655440003")
